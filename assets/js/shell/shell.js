// The interpreter: expands words, wires pipes and redirections, and runs
// commands against the virtual filesystem. Commands live in commands.js.
import { parse, ParseError } from './parse.js';
import { normalise, FsError } from './vfs.js';
import { utf8, text, concat } from '../lib/bytes.js';

const MAX_OUTPUT = 2 * 1024 * 1024;

export class Writer {
  constructor() {
    this.chunks = [];
    this.size = 0;
  }
  write(value) {
    const bytes = typeof value === 'string' ? utf8(value) : value;
    if (this.size + bytes.length > MAX_OUTPUT) throw new Error('output limit reached (2 MB)');
    this.chunks.push(bytes);
    this.size += bytes.length;
  }
  bytes() {
    return concat(...this.chunks);
  }
}

export class ExitSignal extends Error {}

function globToRegExp(pattern) {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\u0000') {
      out += escapeRe(pattern[++i]);
    } else if (ch === '*') out += '[^/]*';
    else if (ch === '?') out += '[^/]';
    else if (ch === '[') {
      const end = pattern.indexOf(']', i + 2);
      if (end < 0) out += '\\[';
      else {
        let body = pattern.slice(i + 1, end).replace(/\u0000/g, '');
        if (body[0] === '!') body = '^' + body.slice(1);
        out += `[${body.replace(/\\/g, '\\\\')}]`;
        i = end;
      }
    } else out += escapeRe(ch);
  }
  return new RegExp(`^${out}$`);
}

function escapeRe(ch) {
  return ch.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

export class Shell {
  constructor({ fs, commands, user = 'learner', cwd, env = {}, hostname = 'socflag', sudoRules = [], onEvent = () => {} }) {
    this.fs = fs;
    this.commands = commands;
    this.user = user;
    this.hostname = hostname;
    this.sudoRules = sudoRules;
    this.onEvent = onEvent;
    const home = fs.user(user).home;
    this.cwd = cwd ?? home;
    this.vars = { HOME: home, USER: user, SHELL: '/bin/bash', PATH: '/usr/local/bin:/usr/bin:/bin', PWD: this.cwd, LANG: 'C.UTF-8', TERM: 'xterm-256color', ...env };
    this.exported = new Set(Object.keys(this.vars));
    this.history = [];
    this.lastExit = 0;
    this.depth = 0;
  }

  prompt() {
    const home = this.fs.user(this.user).home;
    const where = this.cwd === home ? '~' : this.cwd.startsWith(home + '/') ? '~' + this.cwd.slice(home.length) : this.cwd;
    return { user: this.user, host: this.hostname, cwd: where, symbol: this.user === 'root' ? '#' : '$' };
  }

  resolve(path, cwd = this.cwd) {
    return normalise(path, cwd);
  }

  // Runs one line typed by the learner. Returns what a terminal would show.
  execute(line) {
    const trimmed = line.trim();
    if (trimmed) this.history.push(trimmed);
    const out = [];
    const tty = {
      stdout: { write: (value) => void out.push({ stream: 'out', text: typeof value === 'string' ? value : text(value) }) },
      stderr: { write: (value) => void out.push({ stream: 'err', text: typeof value === 'string' ? value : text(value) }) }
    };
    try {
      this.runLine(line, { stdout: tty.stdout, stderr: tty.stderr, isTTY: true });
    } catch (error) {
      if (error instanceof ExitSignal) out.push({ stream: 'err', text: error.message + '\n' });
      else throw error;
    }
    return { chunks: out, exit: this.lastExit };
  }

  runLine(line, io) {
    let list;
    try {
      list = parse(line);
    } catch (error) {
      if (!(error instanceof ParseError)) throw error;
      io.stderr.write(`bash: ${error.message}\n`);
      this.lastExit = 2;
      return 2;
    }
    for (const { connector, pipeline } of list) {
      if (connector === '&&' && this.lastExit !== 0) continue;
      if (connector === '||' && this.lastExit === 0) continue;
      this.lastExit = this.runPipeline(pipeline, io);
    }
    return this.lastExit;
  }

  runPipeline(pipeline, io) {
    let input = null;
    let status = 0;
    pipeline.forEach((command, index) => {
      const last = index === pipeline.length - 1;
      const capture = last ? null : new Writer();
      status = this.runCommand(command, {
        stdin: input,
        stdout: capture ?? io.stdout,
        stderr: io.stderr,
        isTTY: last && io.isTTY
      });
      input = capture ? capture.bytes() : null;
    });
    return status;
  }

  expandWord(word, { glob = true } = {}) {
    // Builds one or more fields from the word's parts. Glob characters that
    // came from quoted text are marked with \u0000 so they stay literal.
    let fields = [{ value: '', pattern: '', hasGlob: false, quotedEmpty: false }];
    const append = (value, quoted) => {
      const current = fields[fields.length - 1];
      current.value += value;
      current.pattern += quoted ? value.replace(/[*?[\]]/g, '\u0000$&') : value;
      if (!quoted && /[*?[]/.test(value)) current.hasGlob = true;
      if (quoted) current.quotedEmpty = true;
    };
    word.parts.forEach((part, index) => {
      if (part.kind === 'lit') {
        let value = part.value;
        if (index === 0 && !part.quoted && (value === '~' || value.startsWith('~/'))) value = this.vars.HOME + value.slice(1);
        append(value, part.quoted);
        if (part.quoted) fields[fields.length - 1].quotedEmpty = true;
        return;
      }
      let value = part.kind === 'var' ? this.variable(part.value) : this.substitute(part.value);
      if (part.quoted) {
        append(value, true);
        return;
      }
      const pieces = value.split(/[ \t\n]+/);
      pieces.forEach((piece, i) => {
        if (i > 0) fields.push({ value: '', pattern: '', hasGlob: false, quotedEmpty: false });
        append(piece, false);
      });
    });
    const result = [];
    for (const field of fields) {
      if (!field.value && !field.quotedEmpty) continue;
      if (glob && field.hasGlob) {
        const matches = this.glob(field.pattern);
        if (matches.length) {
          result.push(...matches);
          continue;
        }
      }
      result.push(field.value);
    }
    return result;
  }

  variable(name) {
    if (name === '?') return String(this.lastExit);
    if (name === '$') return '4242';
    if (name === '#') return String(this.positional?.length ?? 0);
    if (name === '@' || name === '*') return (this.positional ?? []).join(' ');
    if (/^\d$/.test(name)) return name === '0' ? 'bash' : this.positional?.[Number(name) - 1] ?? '';
    return this.vars[name] ?? '';
  }

  substitute(source) {
    const capture = new Writer();
    const saved = this.lastExit;
    this.runLine(source, { stdout: capture, stderr: { write: () => {} }, isTTY: false });
    const value = text(capture.bytes()).replace(/\n+$/, '');
    this.lastExit = saved;
    return value;
  }

  glob(pattern) {
    const absolute = pattern.startsWith('/');
    const segments = pattern.split('/').filter(Boolean);
    let candidates = [absolute ? '/' : ''];
    for (const segment of segments) {
      const next = [];
      const literal = !/[*?[]/.test(segment.replace(/\u0000./g, ''));
      for (const base of candidates) {
        const dir = base === '' ? this.cwd : this.resolve(base, this.cwd);
        const join = (name) => (base === '' ? name : base === '/' ? `/${name}` : `${base}/${name}`);
        if (literal) {
          const name = segment.replace(/\u0000/g, '');
          if (name === '.' || name === '..' || this.fs.exists(this.resolve(join(name)))) next.push(join(name));
          continue;
        }
        let entries;
        try {
          entries = this.fs.list(dir, this.user);
        } catch {
          continue;
        }
        const re = globToRegExp(segment);
        const showHidden = segment.replace(/\u0000/g, '').startsWith('.');
        for (const entry of entries) {
          if (entry.name.startsWith('.') && !showHidden) continue;
          if (re.test(entry.name)) next.push(join(entry.name));
        }
      }
      candidates = next;
      if (!candidates.length) break;
    }
    return candidates.filter(Boolean).sort();
  }

  runCommand(command, io) {
    const words = [...command.words];
    const assignments = [];
    while (words.length) {
      const first = words[0].parts[0];
      const match = first && first.kind === 'lit' && !first.quoted && /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(first.value);
      if (!match) break;
      const rest = { parts: [{ ...first, value: first.value.slice(match[0].length) }, ...words[0].parts.slice(1)] };
      assignments.push([match[1], this.expandWord(rest, { glob: false }).join(' ')]);
      words.shift();
    }

    let argv;
    try {
      argv = words.flatMap((word) => this.expandWord(word));
    } catch (error) {
      io.stderr.write(`bash: ${error.message}\n`);
      return 1;
    }

    // Redirections.
    let stdin = io.stdin;
    let stdout = io.stdout;
    let stderr = io.stderr;
    let isTTY = io.isTTY;
    const pending = [];
    for (const redirect of command.redirects) {
      if (redirect.op === '2>&1') {
        stderr = stdout;
        continue;
      }
      const target = this.expandWord(redirect.target)[0] ?? '';
      if (redirect.op === '<') {
        if (target === '/dev/null') {
          stdin = new Uint8Array();
          continue;
        }
        try {
          stdin = this.fs.readFile(this.resolve(target), this.user);
        } catch (error) {
          io.stderr.write(`bash: ${target}: ${error.message}\n`);
          return 1;
        }
        continue;
      }
      const sink = new Writer();
      const append = redirect.op.endsWith('>>');
      if (target !== '/dev/null') pending.push({ path: this.resolve(target), sink, append, label: target });
      if (redirect.op.startsWith('2')) stderr = sink;
      else if (redirect.op === '&>') {
        stdout = sink;
        stderr = sink;
        isTTY = false;
      } else {
        stdout = sink;
        isTTY = false;
      }
    }
    // Create or truncate redirection targets before the command runs, like Bash.
    for (const item of pending) {
      try {
        this.fs.writeFile(item.path, new Uint8Array(), this.user, { append: true });
        if (!item.append) this.fs.writeFile(item.path, new Uint8Array(), this.user);
      } catch (error) {
        io.stderr.write(`bash: ${item.label}: ${error.message}\n`);
        return 1;
      }
    }

    if (!argv.length) {
      for (const [name, value] of assignments) this.vars[name] = value;
      return 0;
    }

    const savedVars = assignments.length ? { ...this.vars } : null;
    for (const [name, value] of assignments) this.vars[name] = value;
    let status;
    try {
      status = this.execArgv(argv, { stdin, stdout, stderr, isTTY });
    } finally {
      if (savedVars) this.vars = savedVars;
    }

    for (const item of pending) {
      try {
        this.fs.writeFile(item.path, item.sink.bytes(), this.user, { append: true });
      } catch (error) {
        io.stderr.write(`bash: ${item.label}: ${error.message}\n`);
      }
    }
    return status;
  }

  // Runs an already expanded argument list. Also used by sudo, xargs and find -exec.
  execArgv(argv, io, { user = this.user } = {}) {
    const [name, ...args] = argv;
    const previousUser = this.user;
    this.user = user;
    let status;
    try {
      status = this.dispatch(name, args, io);
    } catch (error) {
      if (error instanceof ExitSignal) throw error;
      if (error instanceof FsError) {
        io.stderr.write(`${name}: ${error.message}\n`);
        status = 1;
      } else if (error.message?.startsWith('output limit')) {
        io.stderr.write(`${name}: ${error.message}\n`);
        status = 1;
      } else {
        throw error;
      }
    } finally {
      this.user = previousUser;
    }
    this.onEvent({ type: 'command', name: name.split('/').pop(), args, exit: status, user, cwd: this.cwd });
    return status;
  }

  dispatch(name, args, io) {
    const ctx = {
      name,
      args,
      stdin: io.stdin,
      stdout: io.stdout,
      stderr: io.stderr,
      isTTY: io.isTTY,
      shell: this,
      fs: this.fs,
      user: this.user,
      cwd: this.cwd,
      resolve: (path) => this.resolve(path),
      err: (message) => {
        io.stderr.write(`${name.split('/').pop()}: ${message}\n`);
        return 1;
      }
    };

    if (name.includes('/')) {
      const path = this.resolve(name);
      let node;
      try {
        node = this.fs.lookup(path, this.user);
      } catch (error) {
        io.stderr.write(`bash: ${name}: ${error.message}\n`);
        return error.code === 'EACCES' ? 126 : 127;
      }
      if (node.type === 'dir') {
        io.stderr.write(`bash: ${name}: Is a directory\n`);
        return 126;
      }
      if (!this.fs.allowed(node, this.user, 1)) {
        io.stderr.write(`bash: ${name}: Permission denied\n`);
        return 126;
      }
      const builtin = /^\/(usr\/)?bin\//.test(path) && this.commands[path.split('/').pop()];
      if (builtin) return builtin({ ...ctx, name: path.split('/').pop() });
      if (!this.fs.allowed(node, this.user, 4)) {
        io.stderr.write(`bash: ${name}: Permission denied\n`);
        return 126;
      }
      return this.runScript(path, args, io);
    }

    const command = this.commands[name];
    if (!command) {
      const suggestion = { dir: 'ls', cls: 'clear', type: 'cat', ipconfig: 'ip addr', copy: 'cp', move: 'mv', del: 'rm' }[name];
      io.stderr.write(`${name}: command not found${suggestion ? `. On Linux, try ${suggestion}` : ''}\n`);
      return 127;
    }
    return command(ctx);
  }

  runScript(path, args, io) {
    if (this.depth > 8) {
      io.stderr.write('bash: maximum script depth reached\n');
      return 1;
    }
    const source = text(this.fs.readFile(path, this.user));
    const savedPositional = this.positional;
    this.positional = args;
    this.depth++;
    let status = 0;
    try {
      for (const line of source.split('\n')) {
        if (!line.trim() || line.trim().startsWith('#')) continue;
        status = this.runLine(line, { ...io });
      }
    } finally {
      this.depth--;
      this.positional = savedPositional;
    }
    return status;
  }

  // sudo rules look like { runAs: 'root', command: '/usr/bin/cat /var/log/*' }.
  // The match is a plain glob over the whole command line, which is exactly
  // why rules written like that are dangerous.
  sudoAllows(argv) {
    const line = argv.join(' ');
    return this.sudoRules.find((rule) => {
      const re = new RegExp('^' + rule.command.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
      return re.test(line);
    });
  }
}
