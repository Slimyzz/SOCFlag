// The commands available in the practice shell. Each one receives a context
// with args, stdin, stdout and stderr and returns an exit status, the same
// contract as a real program. Behaviour follows GNU coreutils for the options
// the lessons use; anything unsupported says so instead of guessing.
import { text, utf8, concat, toHex, fromHex, toBase64, fromBase64, isPrintable, looksBinary } from '../lib/bytes.js';
import { md5, sha1, sha256 } from '../lib/hash.js';
import { basename, dirname } from './vfs.js';
import { ExitSignal, Writer } from './shell.js';

const ANSI = { dir: '\x1b[1;34m', exec: '\x1b[1;32m', match: '\x1b[1;31m', file: '\x1b[35m', reset: '\x1b[0m' };
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Parses short and long options. `valued` lists options that take a value.
function options(args, { flags = '', valued = '', long = {} } = {}) {
  const set = new Set();
  const values = {};
  const operands = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') {
      operands.push(...args.slice(i + 1));
      break;
    }
    if (arg.startsWith('--') && arg.length > 2) {
      const [key, inline] = arg.slice(2).split(/=(.*)/s);
      const mapped = long[key];
      if (mapped === undefined) throw new UsageError(`unrecognised option '--${key}'`);
      if (valued.includes(mapped)) values[mapped] = inline ?? args[++i];
      else set.add(mapped);
      continue;
    }
    if (arg.startsWith('-') && arg.length > 1 && !/^-\d/.test(arg)) {
      for (let j = 1; j < arg.length; j++) {
        const ch = arg[j];
        if (valued.includes(ch)) {
          const rest = arg.slice(j + 1);
          values[ch] = rest || args[++i];
          if (values[ch] === undefined) throw new UsageError(`option requires an argument -- '${ch}'`);
          break;
        }
        if (!flags.includes(ch)) throw new UsageError(`invalid option -- '${ch}'`);
        set.add(ch);
      }
      continue;
    }
    operands.push(arg);
  }
  return { has: (flag) => set.has(flag), values, operands };
}

class UsageError extends Error {}

function wrap(fn) {
  return (ctx) => {
    try {
      const status = fn(ctx);
      return typeof status === 'number' ? status : 0;
    } catch (error) {
      if (error instanceof UsageError) {
        ctx.stderr.write(`${ctx.name}: ${error.message}\nTry 'man ${ctx.name}' for the options this shell supports.\n`);
        return 2;
      }
      throw error;
    }
  };
}

// Reads each named file, or stdin when no file (or "-") is given.
function* inputs(ctx, files) {
  if (!files.length || (files.length === 1 && files[0] === '-')) {
    yield { name: '-', bytes: ctx.stdin ?? new Uint8Array() };
    return;
  }
  for (const name of files) {
    if (name === '-') {
      yield { name, bytes: ctx.stdin ?? new Uint8Array() };
      continue;
    }
    if (name === '/dev/null') {
      yield { name, bytes: new Uint8Array() };
      continue;
    }
    try {
      yield { name, bytes: ctx.fs.readFile(ctx.resolve(name), ctx.user) };
    } catch (error) {
      ctx.stderr.write(`${ctx.name}: ${name}: ${error.message}\n`);
      ctx.failed = true;
    }
  }
}

function lines(value) {
  const str = typeof value === 'string' ? value : text(value);
  if (!str) return [];
  const parts = str.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts;
}

function modeString(node) {
  const type = node.type === 'dir' ? 'd' : '-';
  const bits = 'rwxrwxrwx'.split('').map((ch, i) => (node.mode & (1 << (8 - i)) ? ch : '-'));
  if (node.mode & 0o1000) bits[8] = bits[8] === 'x' ? 't' : 'T';
  if (node.mode & 0o4000) bits[2] = bits[2] === 'x' ? 's' : 'S';
  return type + bits.join('');
}

function formatTime(ms, now) {
  const d = new Date(ms);
  const day = String(d.getUTCDate()).padStart(2, ' ');
  const recent = Math.abs(now - ms) < 180 * 86400000;
  const tail = recent ? `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}` : ` ${d.getUTCFullYear()}`;
  return `${MONTHS[d.getUTCMonth()]} ${day} ${tail}`;
}

// Dates like "2026-03-13 02:40" or "2026-03-13T02:40:00Z". Without a zone, UTC.
function parseDate(value) {
  const v = String(value).trim().replace(' ', 'T');
  return Date.parse(/(Z|[+-]\d\d:?\d\d)$/.test(v) ? v : `${v}Z`);
}

function human(size) {
  if (size < 1024) return String(size);
  const units = ['K', 'M', 'G'];
  let value = size, unit = -1;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return (value < 10 ? value.toFixed(1) : Math.round(value)) + units[unit];
}

function colourName(node, name, ctx) {
  if (!ctx.isTTY) return name;
  if (node.type === 'dir') return ANSI.dir + name + ANSI.reset;
  if (node.mode & 0o111) return ANSI.exec + name + ANSI.reset;
  return name;
}

// Converts grep's basic regular expression syntax to JavaScript.
function toRegExp(pattern, { extended, fixed, ignoreCase, word, global = false }) {
  let source;
  if (fixed) source = pattern.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  else {
    source = pattern
      .replace(/\[\[:(alpha|digit|alnum|upper|lower|space|punct|xdigit):\]\]/g, (_, cls) => `[${CLASSES[cls]}]`)
      .replace(/\[:(alpha|digit|alnum|upper|lower|space|punct|xdigit):\]/g, (_, cls) => CLASSES[cls]);
    if (!extended) {
      source = source.replace(/\\([|(){}+?])|([|(){}+?])/g, (_, escaped, plain) => (escaped ? escaped : '\\' + plain));
    }
  }
  if (word) source = `\\b(?:${source})\\b`;
  return new RegExp(source, (ignoreCase ? 'i' : '') + (global ? 'g' : ''));
}

const CLASSES = {
  alpha: 'A-Za-z', digit: '0-9', alnum: 'A-Za-z0-9', upper: 'A-Z', lower: 'a-z',
  space: ' \\t\\n\\r\\f\\v', punct: '!-\\/:-@\\[-`{-~', xdigit: '0-9A-Fa-f'
};

// Signature table used by file and binwalk.
const SIGNATURES = [
  { magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], label: 'PNG image data', short: 'PNG image' },
  { magic: [0xff, 0xd8, 0xff], label: 'JPEG image data', short: 'JPEG image' },
  { magic: [0x47, 0x49, 0x46, 0x38], label: 'GIF image data', short: 'GIF image' },
  { magic: [0x25, 0x50, 0x44, 0x46, 0x2d], label: 'PDF document', short: 'PDF document' },
  { magic: [0x50, 0x4b, 0x03, 0x04], label: 'Zip archive data', short: 'Zip archive' },
  { magic: [0x1f, 0x8b], label: 'gzip compressed data', short: 'gzip data' },
  { magic: [0x7f, 0x45, 0x4c, 0x46], label: 'ELF 64-bit LSB executable, x86-64', short: 'ELF executable' },
  { magic: [0x4d, 0x5a], label: 'PE32 executable (MS Windows)', short: 'Windows executable', strictStart: true },
  { magic: [...utf8('SQLite format 3')], label: 'SQLite 3.x database', short: 'SQLite database' },
  { magic: [0xd4, 0xc3, 0xb2, 0xa1], label: 'pcap capture file, microsecond ts (little-endian)', short: 'pcap capture' },
  { magic: [0x42, 0x5a, 0x68], label: 'bzip2 compressed data', short: 'bzip2 data' },
  { magic: [...utf8('-----BEGIN ')], label: 'PEM certificate or key', short: 'PEM block' }
];

function matchesAt(bytes, magic, offset) {
  for (let i = 0; i < magic.length; i++) if (bytes[offset + i] !== magic[i]) return false;
  return true;
}

function describe(bytes) {
  if (!bytes.length) return 'empty';
  const hit = SIGNATURES.find((sig) => matchesAt(bytes, sig.magic, 0));
  if (hit) {
    if (hit.short === 'PNG image' && bytes.length > 24) {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      return `${hit.label}, ${view.getUint32(16)} x ${view.getUint32(20)}, 8-bit/color RGBA, non-interlaced`;
    }
    return hit.label;
  }
  const str = text(bytes.subarray(0, 4096));
  if (str.startsWith('#!')) return `${str.slice(2).split('\n')[0].trim().split('/').pop()} script, ASCII text executable`;
  if (looksBinary(bytes)) return 'data';
  if (/^\s*[{[]/.test(str)) {
    try {
      JSON.parse(text(bytes));
      return 'JSON text data';
    } catch {}
  }
  const ascii = bytes.every((b) => b < 0x80);
  const longLines = lines(str).some((l) => l.length > 300);
  const kind = /^\s*<(!doctype html|html|head|body|script)\b/i.test(str) ? 'HTML document, ' : /^\s*<\?xml\b/.test(str) ? 'XML document, ' : '';
  return `${kind}${ascii ? 'ASCII' : 'Unicode text, UTF-8'}${ascii ? ' text' : ''}${longLines ? ', with very long lines' : ''}`;
}

function parseSize(value) {
  const match = /^([+-]?)(\d+)([ckMG]?)$/.exec(value ?? '');
  if (!match) throw new UsageError(`invalid argument '${value}' to '-size'`);
  const unit = { '': 512, c: 1, k: 1024, M: 1024 ** 2, G: 1024 ** 3 }[match[3]];
  return { sign: match[1], amount: Number(match[2]), unit };
}

const MANUAL = {
  ls: 'ls [-a] [-l] [-h] [-R] [-t] [-S] [-r] [-d] [-1] [path...]\n  List directory contents. -a shows hidden names that start with a dot. -l shows permissions, owner, size and time.',
  cd: 'cd [dir]\n  Change the current directory. "cd" alone goes home, "cd -" goes back, ".." is the parent.',
  pwd: 'pwd\n  Print the current working directory.',
  cat: 'cat [-n] [file...]\n  Print files one after another. -n numbers the lines. With no file, reads stdin.',
  head: 'head [-n N] [-c N] [file...]\n  Print the first 10 lines, or N lines or bytes.',
  tail: 'tail [-n N] [-n +N] [-c N] [file...]\n  Print the last 10 lines. "+N" starts from line N instead.',
  grep: 'grep [-i] [-v] [-n] [-c] [-l] [-r] [-o] [-w] [-E] [-F] [-a] [-h] [-e pattern] [-f patternfile] pattern [file...]\n  Print lines that match a pattern. -r searches directories, -i ignores case, -v inverts, -o prints only the match, -E enables extended regular expressions, -f reads patterns from a file, one per line.',
  find: 'find [path...] [-name P] [-iname P] [-type f|d] [-size [+-]N[ckM]] [-perm MODE] [-user U] [-group G] [-newer F] [-newermt DATE] [-mtime [+-]N] [-maxdepth N] [-empty] [-executable] [!|-not] [-o] [-exec cmd {} \\;]\n  Walk a directory tree and print paths that pass every test.',
  wc: 'wc [-l] [-w] [-c] [file...]\n  Count lines, words and bytes.',
  sort: 'sort [-n] [-r] [-u] [-k N] [-t SEP] [file...]\n  Sort lines. -n compares numbers, -k picks a field.',
  uniq: 'uniq [-c] [-d] [-u] [-i] [file]\n  Collapse adjacent repeated lines. Sort first so repeats are adjacent. -c counts them.',
  cut: 'cut -d SEP -f LIST | -c LIST [file...]\n  Print selected fields or characters, for example -d: -f1,3.',
  tr: "tr [-d] [-s] SET1 [SET2]\n  Translate or delete characters from stdin. Ranges like a-z work, so tr 'A-Za-z' 'N-ZA-Mn-za-m' is ROT13.",
  base64: 'base64 [-d] [-w COLS] [file]\n  Encode to Base64, or decode with -d.',
  xxd: 'xxd [-p] [-r] [-l N] [-s N] [-c N] [file]\n  Hex dump. -p prints plain hex, -r turns a hex dump back into bytes.',
  hexdump: 'hexdump -C [file]\n  Canonical hex plus ASCII dump.',
  file: 'file FILE...\n  Guess what a file contains by looking at its first bytes, not its name.',
  strings: 'strings [-n MIN] [file...]\n  Print runs of printable characters at least MIN (default 4) long.',
  sha256sum: 'sha256sum [-c] [file...]\n  Print the SHA-256 digest of each file or stdin. With -c, read lines of "digest  file" and check that each file still matches.',
  md5sum: 'md5sum [-c] [file...]\n  Print the MD5 digest of each file or stdin.',
  sha1sum: 'sha1sum [file...]\n  Print the SHA-1 digest of each file or stdin.',
  echo: 'echo [-n] [-e] [text...]\n  Print text. -n drops the newline, -e understands \\n and \\t.',
  printf: 'printf FORMAT [arg...]\n  Formatted output with %s, %d, %x, %c and escapes like \\n.',
  awk: "awk [-F SEP] 'PROGRAM' [file...]\n  This shell supports the common subset: an optional pattern (/regex/, $N == \"x\", $N ~ /re/, NR > N) followed by { print ... } using $0, $N, $NF and NR.",
  sed: "sed [-n] [-E] 'SCRIPT' [file...]\n  Supports s/old/new/[gip], Np, Nd, /re/p and /re/d.",
  rev: 'rev [file...]\n  Reverse each line character by character.',
  tac: 'tac [file...]\n  Print lines in reverse order.',
  chmod: 'chmod MODE FILE...\n  Change permission bits, for example chmod 600 notes.txt or chmod u+x run.sh.',
  sudo: 'sudo -l | sudo COMMAND\n  Run a command as root if a sudo rule allows it. sudo -l lists the rules for your user.',
  dd: 'dd if=FILE [of=FILE] [bs=N] [skip=N] [count=N]\n  Copy a byte range. With bs=1, skip and count are byte offsets, which is handy for carving.',
  binwalk: 'binwalk FILE\n  Scan a file for known signatures at any offset, which finds files hidden inside other files.',
  exiftool: 'exiftool FILE\n  Print metadata, including PNG text chunks.',
  xargs: 'xargs COMMAND [arg...]\n  Read words from stdin and append them as arguments to COMMAND.',
  stat: 'stat FILE...\n  Show size, permissions, owner and modification time.',
  id: 'id [user]\n  Show user and group ids.',
  history: 'history\n  Show commands typed in this session.',
  tee: 'tee [-a] FILE\n  Copy stdin to a file and to stdout.'
};

export function createCommands() {
  const c = {};

  c.help = wrap((ctx) => {
    const names = Object.keys(c).filter((n) => !['help'].includes(n)).sort();
    ctx.stdout.write('Commands in this practice shell:\n\n');
    for (let i = 0; i < names.length; i += 8) ctx.stdout.write('  ' + names.slice(i, i + 8).map((n) => n.padEnd(10)).join('') + '\n');
    ctx.stdout.write('\nType "man <command>" for usage. Pipes (|), redirection (>, >>, <, 2>/dev/null), && and ; work as in Bash.\n');
  });

  c.man = wrap((ctx) => {
    const topic = ctx.args[0];
    if (!topic) return ctx.err('which manual page do you want? Try: man grep');
    if (!MANUAL[topic]) return ctx.err(`no manual entry for ${topic}${c[topic] ? '. It takes no options here.' : ''}`);
    ctx.stdout.write(`${MANUAL[topic]}\n`);
  });

  c.pwd = wrap((ctx) => ctx.stdout.write(ctx.shell.cwd + '\n'));

  c.cd = wrap((ctx) => {
    const shell = ctx.shell;
    let target = ctx.args[0] ?? shell.vars.HOME;
    if (target === '-') {
      target = shell.vars.OLDPWD ?? shell.cwd;
      ctx.stdout.write(target + '\n');
    }
    const path = ctx.resolve(target);
    const node = ctx.fs.lookup(path, ctx.user);
    if (node.type !== 'dir') return ctx.err(`${target}: Not a directory`);
    if (!ctx.fs.allowed(node, ctx.user, 1)) return ctx.err(`${target}: Permission denied`);
    shell.vars.OLDPWD = shell.cwd;
    shell.cwd = path;
    shell.vars.PWD = path;
  });

  c.ls = wrap((ctx) => {
    const fullTime = ctx.args.includes('--full-time');
    const o = options(ctx.args.filter((a) => a !== '--full-time'), { flags: 'alhRtSrdA1F', long: { all: 'a', 'human-readable': 'h', recursive: 'R', reverse: 'r', directory: 'd', 'almost-all': 'A' } });
    const targets = o.operands.length ? o.operands : ['.'];
    const showAll = o.has('a'), almostAll = o.has('A');
    const long = o.has('l') || fullTime;
    const stamp = (ms) => (fullTime ? new Date(ms).toISOString().replace('T', ' ').replace(/\.(\d+)Z$/, '.$1000000 +0000') : formatTime(ms, now));
    const now = ctx.fs.now;
    let status = 0;

    const render = (entries) => {
      if (o.has('t')) entries.sort((a, b) => b.node.mtime - a.node.mtime);
      if (o.has('S')) entries.sort((a, b) => (b.node.data?.length ?? 4096) - (a.node.data?.length ?? 4096));
      if (o.has('r')) entries.reverse();
      if (long) {
        const sizes = entries.map((e) => (o.has('h') ? human(e.node.type === 'dir' ? 4096 : e.node.data.length) : String(e.node.type === 'dir' ? 4096 : e.node.data.length)));
        const width = Math.max(1, ...sizes.map((s) => s.length));
        const owner = Math.max(1, ...entries.map((e) => e.node.owner.length));
        const group = Math.max(1, ...entries.map((e) => e.node.group.length));
        if (entries.length && !o.has('d')) {
          const blocks = entries.reduce((sum, e) => sum + Math.ceil((e.node.data?.length ?? 4096) / 4096) * 4, 0);
          ctx.stdout.write(`total ${blocks}\n`);
        }
        entries.forEach((e, i) => {
          const links = e.node.type === 'dir' ? 2 + [...e.node.children.values()].filter((n) => n.type === 'dir').length : 1;
          ctx.stdout.write(`${modeString(e.node)} ${String(links).padStart(2)} ${e.node.owner.padEnd(owner)} ${e.node.group.padEnd(group)} ${sizes[i].padStart(width)} ${stamp(e.node.mtime)} ${colourName(e.node, e.name, ctx)}${o.has('F') && e.node.type === 'dir' ? '/' : ''}\n`);
        });
      } else if (entries.length) {
        const names = entries.map((e) => colourName(e.node, e.name, ctx) + (o.has('F') && e.node.type === 'dir' ? '/' : ''));
        ctx.stdout.write(ctx.isTTY && !o.has('1') ? names.join('  ') + '\n' : names.join('\n') + '\n');
      }
    };

    const listDir = (path, label, printHeader) => {
      let node;
      try {
        node = ctx.fs.lookup(path, ctx.user);
      } catch (error) {
        ctx.stderr.write(`ls: cannot access '${label}': ${error.message}\n`);
        status = 2;
        return;
      }
      if (node.type !== 'dir' || o.has('d')) {
        render([{ name: label, node }]);
        return;
      }
      let children;
      try {
        children = ctx.fs.list(path, ctx.user);
      } catch (error) {
        ctx.stderr.write(`ls: cannot open directory '${label}': ${error.message}\n`);
        status = 2;
        return;
      }
      if (printHeader) ctx.stdout.write(`${label}:\n`);
      const entries = children.filter((n) => showAll || almostAll || !n.name.startsWith('.')).map((n) => ({ name: n.name, node: n }));
      if (showAll) entries.unshift({ name: '.', node }, { name: '..', node: node.parent });
      render(entries);
      if (o.has('R')) {
        for (const child of children) {
          if (child.type !== 'dir' || (child.name.startsWith('.') && !showAll && !almostAll)) continue;
          ctx.stdout.write('\n');
          const childLabel = label === '/' ? `/${child.name}` : `${label}/${child.name}`;
          listDir(`${path === '/' ? '' : path}/${child.name}`, childLabel, true);
        }
      }
    };

    const files = [];
    const dirs = [];
    for (const target of targets) {
      try {
        const node = ctx.fs.lookup(ctx.resolve(target), ctx.user);
        (node.type === 'dir' && !o.has('d') ? dirs : files).push({ name: target, node });
      } catch (error) {
        ctx.stderr.write(`ls: cannot access '${target}': ${error.message}\n`);
        status = 2;
      }
    }
    if (files.length) render(files);
    dirs.forEach((dir, i) => {
      if (files.length || i > 0) ctx.stdout.write('\n');
      listDir(ctx.resolve(dir.name), dir.name, targets.length > 1 || o.has('R'));
    });
    return status;
  });

  c.cat = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'nAv', long: { number: 'n' } });
    let n = 1;
    for (const { bytes } of inputs(ctx, o.operands)) {
      if (o.has('n')) {
        for (const line of lines(bytes)) ctx.stdout.write(`${String(n++).padStart(6)}\t${line}\n`);
      } else ctx.stdout.write(bytes);
    }
    return ctx.failed ? 1 : 0;
  });
  c.less = c.more = c.cat;

  c.tac = wrap((ctx) => {
    for (const { bytes } of inputs(ctx, ctx.args)) for (const line of lines(bytes).reverse()) ctx.stdout.write(line + '\n');
    return ctx.failed ? 1 : 0;
  });

  const headTail = (isHead) => wrap((ctx) => {
    const args = ctx.args.map((a) => (/^-\d+$/.test(a) ? ['-n', a.slice(1)] : [a])).flat();
    const o = options(args, { valued: 'nc', flags: 'qv', long: { lines: 'n', bytes: 'c' } });
    const files = o.operands;
    for (const { name, bytes } of inputs(ctx, files)) {
      if (files.length > 1) ctx.stdout.write(`==> ${name} <==\n`);
      if (o.values.c !== undefined) {
        const count = Number(o.values.c);
        ctx.stdout.write(isHead ? bytes.subarray(0, count) : bytes.subarray(Math.max(0, bytes.length - count)));
        continue;
      }
      const raw = String(o.values.n ?? '10');
      const all = lines(bytes);
      let picked;
      if (isHead) picked = raw.startsWith('-') ? all.slice(0, Math.max(0, all.length - Number(raw.slice(1)))) : all.slice(0, Number(raw));
      else picked = raw.startsWith('+') ? all.slice(Number(raw.slice(1)) - 1) : all.slice(Math.max(0, all.length - Number(raw)));
      if (picked.length) ctx.stdout.write(picked.join('\n') + '\n');
    }
    return ctx.failed ? 1 : 0;
  });
  c.head = headTail(true);
  c.tail = headTail(false);

  c.echo = wrap((ctx) => {
    let args = [...ctx.args];
    let newline = true, escapes = false;
    while (args.length && /^-[neE]+$/.test(args[0])) {
      if (args[0].includes('n')) newline = false;
      if (args[0].includes('e')) escapes = true;
      args.shift();
    }
    let value = args.join(' ');
    if (escapes) value = unescape(value);
    ctx.stdout.write(value + (newline ? '\n' : ''));
  });

  c.printf = wrap((ctx) => {
    const [format = '', ...rest] = ctx.args;
    const fmt = unescape(format);
    let index = 0;
    let output = '';
    do {
      output += fmt.replace(/%(-?\d*)([sdxXco%])/g, (_, width, type) => {
        if (type === '%') return '%';
        const arg = rest[index++] ?? '';
        let value;
        if (type === 's') value = arg;
        else if (type === 'd') value = String(parseInt(arg, 10) || 0);
        else if (type === 'x') value = (parseInt(arg, 10) || 0).toString(16);
        else if (type === 'X') value = (parseInt(arg, 10) || 0).toString(16).toUpperCase();
        else if (type === 'o') value = (parseInt(arg, 10) || 0).toString(8);
        else value = arg[0] ?? '';
        const w = parseInt(width, 10);
        if (!w) return value;
        return w < 0 ? value.padEnd(-w) : value.padStart(w);
      });
    } while (index > 0 && index < rest.length);
    ctx.stdout.write(latin1Safe(output));
  });

  c.grep = wrap((ctx) => {
    const o = options(ctx.args, {
      flags: 'ivnclLrRoEFwhHaqs',
      valued: 'eABCf',
      long: { 'ignore-case': 'i', 'invert-match': 'v', 'line-number': 'n', count: 'c', recursive: 'r', 'only-matching': 'o', 'extended-regexp': 'E', 'fixed-strings': 'F', 'files-with-matches': 'l', text: 'a', regexp: 'e', quiet: 'q', file: 'f' }
    });
    const operands = [...o.operands];
    // -f reads one pattern per line from a file, which is how you check a
    // log or a list of hashes against a list of known-bad values.
    const patterns = o.values.f !== undefined
      ? lines(ctx.fs.readFile(ctx.resolve(o.values.f), ctx.user)).filter((line) => line.trim() !== '')
      : [o.values.e ?? operands.shift()];
    const pattern = patterns[0];
    if (pattern === undefined) throw new UsageError('no pattern given. Usage: grep PATTERN [FILE...]');
    let re, reGlobal;
    try {
      const settings = { extended: o.has('E'), fixed: o.has('F'), ignoreCase: o.has('i'), word: o.has('w') };
      const source = patterns.map((p) => `(?:${toRegExp(p, settings).source})`).join('|');
      const flags = settings.ignoreCase ? 'i' : '';
      re = new RegExp(source, flags);
      reGlobal = new RegExp(source, `${flags}g`);
    } catch {
      return ctx.err(`invalid regular expression: ${pattern}`) && 2;
    }
    const recursive = o.has('r') || o.has('R');
    const files = [];
    if (!operands.length && recursive) operands.push('.');
    for (const name of operands) {
      if (recursive) {
        for (const item of ctx.fs.walk(ctx.resolve(name), ctx.user, (path, error) => ctx.stderr.write(`grep: ${relative(path, name, ctx)}: ${error.message}\n`))) {
          if (item.node.type === 'file') files.push(relative(item.path, name, ctx));
        }
      } else files.push(name);
    }
    const showNames = !o.has('h') && (o.has('H') || files.length > 1 || recursive);
    let matched = false;
    for (const { name, bytes } of inputs(ctx, files)) {
      if (ctx.fs.exists(ctx.resolve(name)) && name !== '-' && ctx.fs.lookup(ctx.resolve(name)).type === 'dir') {
        ctx.stderr.write(`grep: ${name}: Is a directory\n`);
        continue;
      }
      const binary = !o.has('a') && looksBinary(bytes);
      let count = 0;
      const prefix = showNames ? (ctx.isTTY ? `${ANSI.file}${name}${ANSI.reset}:` : `${name}:`) : '';
      const all = lines(bytes);
      const after = Number(o.values.A ?? o.values.C ?? 0), before = Number(o.values.B ?? o.values.C ?? 0);
      let lastPrinted = -1;
      for (let i = 0; i < all.length; i++) {
        const line = all[i];
        const hit = re.test(line) !== o.has('v');
        if (!hit) continue;
        count++;
        matched = true;
        if (o.has('q') || o.has('c') || o.has('l') || binary) continue;
        if (o.has('o') && !o.has('v')) {
          for (const m of line.matchAll(reGlobal)) if (m[0]) ctx.stdout.write(`${prefix}${o.has('n') ? i + 1 + ':' : ''}${m[0]}\n`);
          continue;
        }
        for (let j = Math.max(lastPrinted + 1, i - before); j < i; j++) ctx.stdout.write(`${prefix}${o.has('n') ? j + 1 + '-' : ''}${all[j]}\n`);
        const shown = ctx.isTTY && !o.has('v') ? line.replace(reGlobal, (m) => ANSI.match + m + ANSI.reset) : line;
        ctx.stdout.write(`${prefix}${o.has('n') ? i + 1 + ':' : ''}${shown}\n`);
        lastPrinted = i;
        for (let j = i + 1; j <= Math.min(all.length - 1, i + after); j++) {
          if (re.test(all[j]) !== o.has('v')) break;
          ctx.stdout.write(`${prefix}${o.has('n') ? j + 1 + '-' : ''}${all[j]}\n`);
          lastPrinted = j;
        }
      }
      if (o.has('q')) continue;
      if (o.has('c')) ctx.stdout.write(`${showNames ? name + ':' : ''}${count}\n`);
      else if (o.has('l') && count) ctx.stdout.write(name + '\n');
      else if (binary && count) ctx.stdout.write(`grep: ${name === '-' ? '(standard input)' : name}: binary file matches\n`);
    }
    if (ctx.failed) return 2;
    return matched ? 0 : 1;
  });

  c.find = wrap((ctx) => {
    const args = [...ctx.args];
    const roots = [];
    while (args.length && !args[0].startsWith('-') && args[0] !== '!' && args[0] !== '(') roots.push(args.shift());
    if (!roots.length) roots.push('.');
    let maxDepth = Infinity, minDepth = 0;
    const groups = [[]];
    let negate = false;
    const execs = [];
    let printed = false;
    while (args.length) {
      const token = args.shift();
      const test = (fn) => {
        const neg = negate;
        groups[groups.length - 1].push((item) => fn(item) !== neg);
        negate = false;
      };
      switch (token) {
        case '!': case '-not': negate = true; break;
        case '-o': case '-or': groups.push([]); break;
        case '-a': case '-and': case '(': case ')': break;
        case '-name': case '-iname': {
          const re = new RegExp('^' + args.shift().replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', token === '-iname' ? 'i' : '');
          test((item) => re.test(item.name));
          break;
        }
        case '-path': {
          const re = new RegExp('^' + args.shift().replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
          test((item) => re.test(item.label));
          break;
        }
        case '-type': {
          const type = args.shift();
          test((item) => (type === 'd' ? item.node.type === 'dir' : type === 'f' ? item.node.type === 'file' : false));
          break;
        }
        case '-size': {
          const { sign, amount, unit } = parseSize(args.shift());
          test((item) => {
            if (item.node.type !== 'file') return false;
            const size = Math.ceil(item.node.data.length / unit);
            return sign === '+' ? size > amount : sign === '-' ? size < amount : size === amount;
          });
          break;
        }
        case '-empty': test((item) => (item.node.type === 'file' ? item.node.data.length === 0 : item.node.children.size === 0)); break;
        case '-executable': test((item) => ctx.fs.allowed(item.node, ctx.user, 1) && item.node.type === 'file'); break;
        case '-readable': test((item) => ctx.fs.allowed(item.node, ctx.user, 4)); break;
        case '-writable': test((item) => ctx.fs.allowed(item.node, ctx.user, 2)); break;
        case '-user': { const u = args.shift(); test((item) => item.node.owner === u); break; }
        case '-group': { const g = args.shift(); test((item) => item.node.group === g); break; }
        case '-perm': {
          const raw = args.shift();
          const mode = parseInt(raw.replace(/^[-/]/, ''), 8);
          test((item) => (raw.startsWith('-') ? (item.node.mode & mode) === mode : raw.startsWith('/') ? (item.node.mode & mode) !== 0 : (item.node.mode & 0o7777) === mode));
          break;
        }
        case '-newer': {
          const ref = ctx.fs.lookup(ctx.resolve(args.shift()), ctx.user);
          test((item) => item.node.mtime > ref.mtime);
          break;
        }
        case '-newermt': {
          const raw = args.shift();
          const limit = parseDate(raw ?? '');
          if (Number.isNaN(limit)) throw new UsageError(`cannot parse date '${raw}'`);
          test((item) => item.node.mtime > limit);
          break;
        }
        case '-mtime': {
          const raw = args.shift();
          const days = Number(raw.replace(/^[+-]/, ''));
          test((item) => {
            const age = Math.floor((ctx.fs.now - item.node.mtime) / 86400000);
            return raw.startsWith('+') ? age > days : raw.startsWith('-') ? age < days : age === days;
          });
          break;
        }
        case '-maxdepth': maxDepth = Number(args.shift()); break;
        case '-mindepth': minDepth = Number(args.shift()); break;
        case '-print': printed = true; break;
        case '-exec': {
          const command = [];
          while (args.length && args[0] !== ';' && args[0] !== '+') command.push(args.shift());
          if (!args.length) throw new UsageError("missing argument to '-exec'. End it with \\;");
          args.shift();
          execs.push(command);
          break;
        }
        default:
          throw new UsageError(`unknown predicate '${token}'`);
      }
    }
    const nonEmpty = groups.filter((g) => g.length);
    const matches = (item) => !nonEmpty.length || nonEmpty.some((group) => group.every((fn) => fn(item)));
    let status = 0;
    for (const root of roots) {
      const start = ctx.resolve(root);
      const onError = (path, error) => {
        ctx.stderr.write(`find: '${relative(path, root, ctx)}': ${error.message}\n`);
        status = 1;
      };
      for (const item of ctx.fs.walk(start, ctx.user, onError)) {
        if (item.depth > maxDepth) continue;
        const label = relative(item.path, root, ctx);
        const entry = { ...item, label, name: item.depth === 0 ? basename(root) : item.node.name };
        if (item.depth < minDepth || !matches(entry)) continue;
        if (execs.length) {
          for (const command of execs) ctx.shell.execArgv(command.map((part) => part.replaceAll('{}', label)), { stdin: null, stdout: ctx.stdout, stderr: ctx.stderr, isTTY: false });
          if (!printed) continue;
        }
        ctx.stdout.write(label + '\n');
      }
    }
    return status;
  });

  c.wc = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'lwcm', long: { lines: 'l', words: 'w', bytes: 'c', chars: 'm' } });
    const pick = o.has('l') || o.has('w') || o.has('c') || o.has('m') ? ['l', 'w', 'c'].filter((f) => o.has(f) || (f === 'c' && o.has('m'))) : ['l', 'w', 'c'];
    const totals = { l: 0, w: 0, c: 0 };
    let count = 0;
    for (const { name, bytes } of inputs(ctx, o.operands)) {
      const str = text(bytes);
      const values = { l: (str.match(/\n/g) ?? []).length, w: str.split(/\s+/).filter(Boolean).length, c: bytes.length };
      for (const key of pick) totals[key] += values[key];
      count++;
      const cols = pick.map((key) => String(values[key]).padStart(pick.length > 1 ? 7 : 0));
      ctx.stdout.write(cols.join(' ') + (name === '-' ? '' : ` ${name}`) + '\n');
    }
    if (count > 1) ctx.stdout.write(pick.map((key) => String(totals[key]).padStart(7)).join(' ') + ' total\n');
    return ctx.failed ? 1 : 0;
  });

  c.sort = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'nrufh', valued: 'kt', long: { numeric: 'n', reverse: 'r', unique: 'u', 'ignore-case': 'f' } });
    let all = [];
    for (const { bytes } of inputs(ctx, o.operands)) all.push(...lines(bytes));
    const field = o.values.k ? parseInt(o.values.k, 10) : 0;
    const key = (line) => {
      if (!field) return line;
      const parts = o.values.t ? line.split(o.values.t) : line.trim().split(/\s+/);
      return parts[field - 1] ?? '';
    };
    const numeric = o.has('n') || o.has('h');
    all.sort((a, b) => {
      const ka = key(a), kb = key(b);
      if (numeric) return (parseFloat(ka) || 0) - (parseFloat(kb) || 0) || a.localeCompare(b);
      return o.has('f') ? ka.toLowerCase().localeCompare(kb.toLowerCase()) : ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    if (o.has('r')) all.reverse();
    if (o.has('u')) all = all.filter((line, i) => i === 0 || key(line) !== key(all[i - 1]));
    if (all.length) ctx.stdout.write(all.join('\n') + '\n');
  });

  c.uniq = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'cdui', long: { count: 'c' } });
    const groups = [];
    for (const { bytes } of inputs(ctx, o.operands.slice(0, 1))) {
      for (const line of lines(bytes)) {
        const last = groups[groups.length - 1];
        const same = last && (o.has('i') ? last.line.toLowerCase() === line.toLowerCase() : last.line === line);
        if (same) last.count++;
        else groups.push({ line, count: 1 });
      }
    }
    for (const g of groups) {
      if (o.has('d') && g.count < 2) continue;
      if (o.has('u') && g.count > 1) continue;
      ctx.stdout.write(o.has('c') ? `${String(g.count).padStart(7)} ${g.line}\n` : `${g.line}\n`);
    }
  });

  c.cut = wrap((ctx) => {
    const o = options(ctx.args, { valued: 'dfc', flags: 's', long: { delimiter: 'd', fields: 'f', characters: 'c' } });
    const list = o.values.f ?? o.values.c;
    if (!list) throw new UsageError('you must specify a list of fields (-f) or characters (-c)');
    const ranges = list.split(',').map((part) => {
      const [a, b] = part.split('-');
      return [a ? Number(a) : 1, part.includes('-') ? (b ? Number(b) : Infinity) : Number(a)];
    });
    const keep = (index) => ranges.some(([a, b]) => index >= a && index <= b);
    const delim = o.values.d ?? '\t';
    for (const { bytes } of inputs(ctx, o.operands)) {
      for (const line of lines(bytes)) {
        if (o.values.c) {
          ctx.stdout.write([...line].filter((_, i) => keep(i + 1)).join('') + '\n');
        } else {
          if (!line.includes(delim)) {
            if (!o.has('s')) ctx.stdout.write(line + '\n');
            continue;
          }
          ctx.stdout.write(line.split(delim).filter((_, i) => keep(i + 1)).join(delim) + '\n');
        }
      }
    }
    return ctx.failed ? 1 : 0;
  });

  c.tr = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'dsc' });
    const expand = (set) => {
      const source = unescape(set ?? '')
        .replace(/\[:upper:\]/g, 'A-Z').replace(/\[:lower:\]/g, 'a-z').replace(/\[:digit:\]/g, '0-9')
        .replace(/\[:alpha:\]/g, 'A-Za-z').replace(/\[:alnum:\]/g, 'A-Za-z0-9').replace(/\[:space:\]/g, ' \t\n\r');
      const out = [];
      for (let i = 0; i < source.length; i++) {
        if (source[i + 1] === '-' && i + 2 < source.length) {
          for (let code = source.charCodeAt(i); code <= source.charCodeAt(i + 2); code++) out.push(String.fromCharCode(code));
          i += 2;
        } else out.push(source[i]);
      }
      return out;
    };
    const [a, b] = o.operands;
    if (a === undefined) throw new UsageError('missing operand');
    const from = expand(a), to = expand(b);
    const input = text(ctx.stdin ?? new Uint8Array());
    let output = '';
    let previous = null;
    for (const ch of input) {
      const index = from.indexOf(ch);
      const inSet = o.has('c') ? index < 0 : index >= 0;
      if (o.has('d') && inSet) continue;
      let next = ch;
      if (!o.has('d') && inSet && to.length) next = to[Math.min(index, to.length - 1)];
      if (o.has('s') && next === previous && (to.length ? to.includes(next) : from.includes(next))) continue;
      output += next;
      previous = next;
    }
    ctx.stdout.write(output);
  });

  c.rev = wrap((ctx) => {
    for (const { bytes } of inputs(ctx, ctx.args)) for (const line of lines(bytes)) ctx.stdout.write([...line].reverse().join('') + '\n');
    return ctx.failed ? 1 : 0;
  });

  c.tee = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'a', long: { append: 'a' } });
    const data = ctx.stdin ?? new Uint8Array();
    for (const name of o.operands) ctx.fs.writeFile(ctx.resolve(name), data, ctx.user, { append: o.has('a') });
    ctx.stdout.write(data);
  });

  c.base64 = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'di', valued: 'w', long: { decode: 'd', wrap: 'w', 'ignore-garbage': 'i' } });
    for (const { bytes } of inputs(ctx, o.operands.slice(0, 1))) {
      if (o.has('d')) {
        const source = text(bytes).replace(/\s+/g, '');
        if (/[^A-Za-z0-9+/=_-]/.test(source) && !o.has('i')) {
          ctx.stderr.write('base64: invalid input\n');
          return 1;
        }
        try {
          ctx.stdout.write(fromBase64(source));
        } catch {
          ctx.stderr.write('base64: invalid input\n');
          return 1;
        }
      } else {
        const encoded = toBase64(bytes);
        const width = Number(o.values.w ?? 76);
        ctx.stdout.write((width ? encoded.match(new RegExp(`.{1,${width}}`, 'g'))?.join('\n') ?? '' : encoded) + '\n');
      }
    }
    return ctx.failed ? 1 : 0;
  });

  c.xxd = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'pru', valued: 'lsc', long: { plain: 'p', revert: 'r' } });
    for (const { bytes } of inputs(ctx, o.operands.slice(0, 1))) {
      if (o.has('r')) {
        const source = text(bytes);
        const hex = o.has('p') ? source : lines(source).map((line) => line.replace(/^[0-9a-f]+:\s*/i, '').slice(0, 39)).join('');
        try {
          ctx.stdout.write(fromHex(hex));
        } catch (error) {
          return ctx.err(error.message);
        }
        continue;
      }
      const start = Number(o.values.s ?? 0);
      const slice = bytes.subarray(start, o.values.l !== undefined ? start + Number(o.values.l) : undefined);
      if (o.has('p')) {
        const hex = toHex(slice);
        ctx.stdout.write((hex.match(/.{1,60}/g) ?? ['']).join('\n') + '\n');
        continue;
      }
      const cols = Number(o.values.c ?? 16);
      for (let i = 0; i < slice.length; i += cols) {
        const row = slice.subarray(i, i + cols);
        const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join('').replace(/(.{4})/g, '$1 ').trimEnd();
        const width = Math.ceil(cols / 2) * 5 - 1;
        ctx.stdout.write(`${(start + i).toString(16).padStart(8, '0')}: ${hex.padEnd(width)}  ${Array.from(row, (b) => (isPrintable(b) ? String.fromCharCode(b) : '.')).join('')}\n`);
      }
    }
    return ctx.failed ? 1 : 0;
  });

  c.hexdump = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'C', valued: 'ns' });
    for (const { bytes } of inputs(ctx, o.operands.slice(0, 1))) {
      const start = Number(o.values.s ?? 0);
      const slice = bytes.subarray(start, o.values.n !== undefined ? start + Number(o.values.n) : undefined);
      for (let i = 0; i < slice.length; i += 16) {
        const row = slice.subarray(i, i + 16);
        const hexes = Array.from(row, (b) => b.toString(16).padStart(2, '0'));
        const left = hexes.slice(0, 8).join(' '), right = hexes.slice(8).join(' ');
        ctx.stdout.write(`${(start + i).toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  |${Array.from(row, (b) => (isPrintable(b) ? String.fromCharCode(b) : '.')).join('')}|\n`);
      }
      ctx.stdout.write(`${(start + slice.length).toString(16).padStart(8, '0')}\n`);
    }
    return ctx.failed ? 1 : 0;
  });

  c.file = wrap((ctx) => {
    if (!ctx.args.length) throw new UsageError('missing file operand');
    for (const name of ctx.args) {
      try {
        const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
        if (node.type === 'dir') {
          ctx.stdout.write(`${name}: directory\n`);
          continue;
        }
        if (!ctx.fs.allowed(node, ctx.user, 4)) {
          ctx.stdout.write(`${name}: regular file, no read permission\n`);
          continue;
        }
        ctx.stdout.write(`${name}: ${describe(node.data)}\n`);
      } catch (error) {
        ctx.stdout.write(`${name}: cannot open '${name}' (${error.message})\n`);
      }
    }
  });

  c.strings = wrap((ctx) => {
    const o = options(ctx.args, { valued: 'nt', flags: 'a' });
    const min = Number(o.values.n ?? 4);
    for (const { bytes } of inputs(ctx, o.operands)) {
      let run = '';
      let at = 0;
      const flush = () => {
        if (run.length >= min) ctx.stdout.write((o.values.t ? at.toString(o.values.t === 'x' ? 16 : 10).padStart(7) + ' ' : '') + run + '\n');
        run = '';
      };
      bytes.forEach((b, i) => {
        if (isPrintable(b) || b === 9) {
          if (!run) at = i;
          run += String.fromCharCode(b);
        } else flush();
      });
      flush();
    }
    return ctx.failed ? 1 : 0;
  });

  const digest = (fn) => wrap((ctx) => {
    const check = ctx.args.some((a) => a === '-c' || a === '--check');
    const files = ctx.args.filter((a) => a !== '-c' && a !== '--check');
    if (!check) {
      for (const { name, bytes } of inputs(ctx, files)) ctx.stdout.write(`${fn(bytes)}  ${name}\n`);
      return ctx.failed ? 1 : 0;
    }
    // -c reads "digest  filename" lines and recomputes each one.
    let bad = 0, unreadable = 0;
    for (const { bytes } of inputs(ctx, files)) {
      for (const line of lines(bytes)) {
        const m = /^([0-9a-fA-F]+)\s+\*?(.+)$/.exec(line.trim());
        if (!m) continue;
        try {
          const ok = fn(ctx.fs.readFile(ctx.resolve(m[2]), ctx.user)) === m[1].toLowerCase();
          ctx.stdout.write(`${m[2]}: ${ok ? 'OK' : 'FAILED'}\n`);
          if (!ok) bad++;
        } catch {
          ctx.stdout.write(`${m[2]}: FAILED open or read\n`);
          unreadable++;
        }
      }
    }
    if (unreadable) ctx.stderr.write(`${ctx.name}: WARNING: ${unreadable} listed file${unreadable === 1 ? '' : 's'} could not be read\n`);
    if (bad) ctx.stderr.write(`${ctx.name}: WARNING: ${bad} computed checksum${bad === 1 ? '' : 's'} did NOT match\n`);
    return bad || unreadable ? 1 : 0;
  });
  c.md5sum = digest(md5);
  c.sha1sum = digest(sha1);
  c.sha256sum = digest(sha256);

  c.awk = wrap((ctx) => {
    const args = [...ctx.args];
    let separator = null;
    while (args[0]?.startsWith('-F')) {
      separator = args[0].length > 2 ? args.shift().slice(2) : (args.shift(), args.shift());
    }
    const program = args.shift();
    if (program === undefined) throw new UsageError('no program given');
    const match = /^\s*(.*?)\s*(\{\s*(.*?)\s*\})?\s*$/s.exec(program);
    const pattern = match[1];
    const action = match[2] ? match[3] : 'print';
    const split = (line) => (separator === null ? line.trim().split(/\s+/).filter(Boolean) : line.split(separator.length === 1 ? separator : new RegExp(separator)));
    const valueOf = (token, fields, line, nr) => {
      token = token.trim();
      if (/^"(.*)"$/s.test(token)) return token.slice(1, -1).replace(/\\t/g, '\t').replace(/\\n/g, '\n');
      if (token === 'NR') return String(nr);
      if (token === 'NF') return String(fields.length);
      if (token === '$0') return line;
      if (token === '$NF') return fields[fields.length - 1] ?? '';
      const field = /^\$(\d+)$/.exec(token);
      if (field) return fields[Number(field[1]) - 1] ?? '';
      if (/^-?\d+(\.\d+)?$/.test(token)) return token;
      throw new UsageError(`this shell's awk does not understand '${token}'. See: man awk`);
    };
    const test = (fields, line, nr) => {
      if (!pattern) return true;
      let m;
      if ((m = /^(!?)\/(.*)\/$/.exec(pattern))) return new RegExp(m[2]).test(line) !== (m[1] === '!');
      if ((m = /^(\$\w+|NR|NF)\s*(!?~)\s*\/(.*)\/$/.exec(pattern))) return new RegExp(m[3]).test(valueOf(m[1], fields, line, nr)) === (m[2] === '~');
      if ((m = /^(\$\w+|NR|NF)\s*(==|!=|>=|<=|>|<)\s*(.+)$/.exec(pattern))) {
        const left = valueOf(m[1], fields, line, nr), right = valueOf(m[3], fields, line, nr);
        const numeric = !isNaN(parseFloat(left)) && !isNaN(parseFloat(right)) && !/^"/.test(m[3].trim());
        const a = numeric ? parseFloat(left) : left, b = numeric ? parseFloat(right) : right;
        return { '==': a === b, '!=': a !== b, '>': a > b, '<': a < b, '>=': a >= b, '<=': a <= b }[m[2]];
      }
      throw new UsageError(`this shell's awk does not understand the pattern '${pattern}'. See: man awk`);
    };
    const actionMatch = /^print\s*(.*)$/s.exec(action.replace(/;\s*$/, ''));
    if (!actionMatch) throw new UsageError(`only print actions are supported here. See: man awk`);
    const expressions = actionMatch[1].trim();
    let nr = 0;
    for (const { bytes } of inputs(ctx, args)) {
      for (const line of lines(bytes)) {
        nr++;
        const fields = split(line);
        if (!test(fields, line, nr)) continue;
        if (!expressions) {
          ctx.stdout.write(line + '\n');
          continue;
        }
        const items = expressions.match(/"(?:[^"\\]|\\.)*"|,|[^\s,"]+/g) ?? [];
        let out = '';
        let pendingSpace = false;
        for (const item of items) {
          if (item === ',') {
            pendingSpace = true;
            continue;
          }
          if (pendingSpace) out += ' ';
          pendingSpace = false;
          out += valueOf(item, fields, line, nr);
        }
        ctx.stdout.write(out + '\n');
      }
    }
    return ctx.failed ? 2 : 0;
  });

  c.sed = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'nEr', valued: 'e' });
    const operands = [...o.operands];
    const script = o.values.e ?? operands.shift();
    if (!script) throw new UsageError('no script given');
    const extended = o.has('E') || o.has('r');
    let m;
    let apply;
    if ((m = /^s(.)(.*?)\1(.*?)\1([gip]*)$/s.exec(script))) {
      const re = toRegExp(m[2], { extended, ignoreCase: m[4].includes('i'), global: m[4].includes('g') });
      const replacement = m[3].replace(/\\(\d)/g, '$$$1').replace(/&/g, '$$&');
      apply = (line) => {
        const changed = line.replace(re, replacement);
        return { line: changed, print: m[4].includes('p') && changed !== line };
      };
    } else if ((m = /^(\d+|\/(.*)\/)([pd])$/.exec(script))) {
      const re = m[2] !== undefined ? toRegExp(m[2], { extended }) : null;
      const target = re ? null : Number(m[1]);
      apply = (line, nr) => {
        const hit = re ? re.test(line) : nr === target;
        if (m[3] === 'd') return hit ? { line: null } : { line };
        return { line, print: hit };
      };
    } else throw new UsageError(`unsupported script '${script}'. See: man sed`);
    let nr = 0;
    for (const { bytes } of inputs(ctx, operands)) {
      for (const line of lines(bytes)) {
        const result = apply(line, ++nr);
        if (result.line === null) continue;
        if (!o.has('n')) ctx.stdout.write(result.line + '\n');
        if (result.print) ctx.stdout.write(result.line + '\n');
      }
    }
    return ctx.failed ? 1 : 0;
  });

  c.touch = wrap((ctx) => {
    const args = [...ctx.args];
    let when = ctx.fs.now;
    // -d sets an exact time, which is handy as a reference point for find -newer.
    const at = args.findIndex((a) => a === '-d' || a.startsWith('--date='));
    if (at >= 0) {
      const value = args[at] === '-d' ? args.splice(at, 2)[1] : args.splice(at, 1)[0].slice(7);
      when = parseDate(value);
      if (Number.isNaN(when)) throw new UsageError(`invalid date format '${value}'`);
    }
    for (const name of args) {
      const path = ctx.resolve(name);
      if (!ctx.fs.exists(path)) ctx.fs.writeFile(path, '', ctx.user);
      ctx.fs.lookup(path, ctx.user).mtime = when;
    }
  });

  c.mkdir = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'p', long: { parents: 'p' } });
    for (const name of o.operands) {
      try {
        ctx.fs.mkdir(ctx.resolve(name), ctx.user, { parents: o.has('p') });
      } catch (error) {
        ctx.stderr.write(`mkdir: cannot create directory '${name}': ${error.message}\n`);
        return 1;
      }
    }
  });

  c.rm = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'rRfi', long: { recursive: 'r', force: 'f' } });
    for (const name of o.operands) {
      try {
        ctx.fs.remove(ctx.resolve(name), ctx.user, { recursive: o.has('r') || o.has('R') });
      } catch (error) {
        if (!(o.has('f') && error.code === 'ENOENT')) ctx.stderr.write(`rm: cannot remove '${name}': ${error.message}\n`);
      }
    }
  });
  c.rmdir = wrap((ctx) => {
    for (const name of ctx.args) {
      const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
      if (node.type !== 'dir') return ctx.err(`failed to remove '${name}': Not a directory`);
      if (node.children.size) return ctx.err(`failed to remove '${name}': Directory not empty`);
      ctx.fs.remove(ctx.resolve(name), ctx.user, { recursive: true });
    }
  });

  c.cp = wrap((ctx) => {
    const o = options(ctx.args, { flags: 'rRpf' });
    const [source, target] = o.operands;
    if (!target) throw new UsageError('missing destination file operand');
    const data = ctx.fs.readFile(ctx.resolve(source), ctx.user);
    let destination = ctx.resolve(target);
    if (ctx.fs.exists(destination) && ctx.fs.lookup(destination, ctx.user).type === 'dir') destination = `${destination}/${basename(source)}`;
    ctx.fs.writeFile(destination, new Uint8Array(data), ctx.user);
  });

  c.mv = wrap((ctx) => {
    const [source, target] = ctx.args.filter((a) => !a.startsWith('-'));
    if (!target) throw new UsageError('missing destination file operand');
    ctx.fs.move(ctx.resolve(source), ctx.resolve(target), ctx.user);
  });

  c.chmod = wrap((ctx) => {
    const [mode, ...files] = ctx.args.filter((a) => a !== '-R');
    if (!files.length) throw new UsageError('missing operand');
    for (const name of files) {
      const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
      if (ctx.fs.user(ctx.user).uid !== 0 && node.owner !== ctx.user) {
        ctx.stderr.write(`chmod: changing permissions of '${name}': Operation not permitted\n`);
        return 1;
      }
      if (/^[0-7]{3,4}$/.test(mode)) node.mode = parseInt(mode, 8);
      else {
        for (const clause of mode.split(',')) {
          const m = /^([ugoa]*)([+-=])([rwxst]*)$/.exec(clause);
          if (!m) throw new UsageError(`invalid mode: '${mode}'`);
          const who = m[1] || 'a';
          let mask = 0;
          for (const p of m[3]) {
            const bit = { r: 4, w: 2, x: 1 }[p];
            if (!bit) continue;
            if (who.includes('u') || who.includes('a')) mask |= bit << 6;
            if (who.includes('g') || who.includes('a')) mask |= bit << 3;
            if (who.includes('o') || who.includes('a')) mask |= bit;
          }
          if (m[2] === '+') node.mode |= mask;
          else if (m[2] === '-') node.mode &= ~mask;
          else node.mode = (node.mode & ~0o777) | mask;
        }
      }
    }
  });

  c.chown = wrap((ctx) => {
    if (ctx.fs.user(ctx.user).uid !== 0) {
      ctx.stderr.write(`chown: changing ownership of '${ctx.args[1] ?? ''}': Operation not permitted\n`);
      return 1;
    }
    const [spec, ...files] = ctx.args;
    const [owner, group] = spec.split(':');
    for (const name of files) {
      const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
      if (owner) node.owner = owner;
      if (group) node.group = group;
    }
  });

  c.stat = wrap((ctx) => {
    for (const name of ctx.args) {
      const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
      const size = node.type === 'dir' ? 4096 : node.data.length;
      const when = new Date(node.mtime).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' +0000');
      ctx.stdout.write(`  File: ${name}\n  Size: ${size}\t${node.type === 'dir' ? 'directory' : 'regular file'}\nAccess: (${(node.mode & 0o7777).toString(8).padStart(4, '0')}/${modeString(node)})  Uid: ${node.owner}  Gid: ${node.group}\nModify: ${when}\n`);
    }
  });

  c.whoami = wrap((ctx) => ctx.stdout.write(ctx.user + '\n'));
  c.id = wrap((ctx) => {
    const user = ctx.fs.user(ctx.args[0] ?? ctx.user);
    const groups = user.groups.map((g) => `${ctx.fs.users[g]?.uid ?? groupId(ctx.fs, g)}(${g})`).join(',');
    ctx.stdout.write(`uid=${user.uid}(${user.name}) gid=${user.uid}(${user.groups[0]}) groups=${groups}\n`);
  });
  c.groups = wrap((ctx) => ctx.stdout.write(ctx.fs.user(ctx.args[0] ?? ctx.user).groups.join(' ') + '\n'));
  c.hostname = wrap((ctx) => ctx.stdout.write(ctx.shell.hostname + '\n'));
  c.uname = wrap((ctx) => ctx.stdout.write(ctx.args.includes('-a') ? `Linux ${ctx.shell.hostname} 6.6.0-socflag #1 SMP x86_64 GNU/Linux\n` : 'Linux\n'));
  c.date = wrap((ctx) => ctx.stdout.write(new Date(ctx.fs.now).toUTCString().replace('GMT', 'UTC') + '\n'));
  c.uptime = wrap((ctx) => ctx.stdout.write(' 10:00:00 up 3 days,  2:14,  1 user,  load average: 0.08, 0.03, 0.01\n'));

  c.env = c.printenv = wrap((ctx) => {
    const vars = ctx.shell.vars;
    if (ctx.args[0]) {
      if (vars[ctx.args[0]] === undefined) return 1;
      ctx.stdout.write(vars[ctx.args[0]] + '\n');
      return 0;
    }
    for (const key of Object.keys(vars).filter((k) => ctx.shell.exported.has(k)).sort()) ctx.stdout.write(`${key}=${vars[key]}\n`);
  });
  c.export = wrap((ctx) => {
    for (const arg of ctx.args) {
      const [name, ...value] = arg.split('=');
      if (value.length) ctx.shell.vars[name] = value.join('=');
      ctx.shell.exported.add(name);
    }
  });
  c.unset = wrap((ctx) => {
    for (const name of ctx.args) delete ctx.shell.vars[name];
  });

  c.history = wrap((ctx) => {
    ctx.shell.history.forEach((line, i) => ctx.stdout.write(`${String(i + 1).padStart(5)}  ${line}\n`));
  });
  c.clear = wrap((ctx) => ctx.stdout.write('\x1b[2J'));
  c.true = () => 0;
  c.false = () => 1;
  c.exit = c.logout = () => {
    throw new ExitSignal('This practice shell stays open. Use Reset to start the workspace again.');
  };

  c.which = wrap((ctx) => {
    let status = 0;
    for (const name of ctx.args) {
      if (c[name] && ctx.fs.exists(`/usr/bin/${name}`)) ctx.stdout.write(`/usr/bin/${name}\n`);
      else status = 1;
    }
    return status;
  });

  c.ps = wrap((ctx) => {
    const procs = ctx.shell.processes ?? [];
    ctx.stdout.write('USER         PID %CPU %MEM COMMAND\n');
    for (const p of [{ user: 'root', pid: 1, command: '/sbin/init' }, ...procs, { user: ctx.user, pid: 4242, command: '-bash' }, { user: ctx.user, pid: 4290, command: 'ps ' + ctx.args.join(' ') }]) {
      ctx.stdout.write(`${p.user.padEnd(10)} ${String(p.pid).padStart(5)}  0.0  0.1 ${p.command}\n`);
    }
  });

  c.sudo = wrap((ctx) => {
    const shell = ctx.shell;
    if (!ctx.args.length) throw new UsageError('usage: sudo -l | sudo COMMAND');
    if (ctx.args[0] === '-l') {
      if (!shell.sudoRules.length) {
        ctx.stdout.write(`Sorry, user ${ctx.user} may not run sudo on ${shell.hostname}.\n`);
        return 1;
      }
      ctx.stdout.write(`User ${ctx.user} may run the following commands on ${shell.hostname}:\n`);
      for (const rule of shell.sudoRules) ctx.stdout.write(`    (root) NOPASSWD: ${rule.command}\n`);
      return 0;
    }
    if (['-i', '-s', 'su', 'bash', 'sh', '-u'].includes(ctx.args[0])) {
      ctx.stderr.write(`Sorry, user ${ctx.user} is not allowed to execute '${ctx.args.join(' ')}' as root on ${shell.hostname}.\n`);
      return 1;
    }
    const argv = [...ctx.args];
    if (!argv[0].includes('/') && c[argv[0]]) argv[0] = `/usr/bin/${argv[0]}`;
    if (!shell.sudoAllows(argv)) {
      ctx.stderr.write(`Sorry, user ${ctx.user} is not allowed to execute '${argv.join(' ')}' as root on ${shell.hostname}.\n`);
      return 1;
    }
    return shell.execArgv(argv, { stdin: ctx.stdin, stdout: ctx.stdout, stderr: ctx.stderr, isTTY: ctx.isTTY }, { user: 'root' });
  });
  c.su = wrap((ctx) => {
    ctx.stderr.write('su: Authentication failure\n');
    return 1;
  });

  c.xargs = wrap((ctx) => {
    const command = ctx.args.length ? ctx.args : ['echo'];
    const words = text(ctx.stdin ?? new Uint8Array()).split(/\s+/).filter(Boolean);
    if (!words.length) return 0;
    return ctx.shell.execArgv([...command, ...words], { stdin: null, stdout: ctx.stdout, stderr: ctx.stderr, isTTY: false });
  });

  c.dd = wrap((ctx) => {
    const params = Object.fromEntries(ctx.args.map((arg) => arg.split('=')));
    const bs = Number(params.bs ?? 512);
    const input = params.if ? ctx.fs.readFile(ctx.resolve(params.if), ctx.user) : ctx.stdin ?? new Uint8Array();
    const start = Number(params.skip ?? 0) * bs;
    const end = params.count !== undefined ? start + Number(params.count) * bs : input.length;
    const slice = input.subarray(start, end);
    if (params.of) ctx.fs.writeFile(ctx.resolve(params.of), new Uint8Array(slice), ctx.user);
    else ctx.stdout.write(slice);
    ctx.stderr.write(`${Math.ceil(slice.length / bs)}+0 records in\n${Math.ceil(slice.length / bs)}+0 records out\n${slice.length} bytes copied\n`);
  });

  c.binwalk = wrap((ctx) => {
    if (!ctx.args.length) throw new UsageError('missing file operand');
    for (const name of ctx.args) {
      const bytes = ctx.fs.readFile(ctx.resolve(name), ctx.user);
      ctx.stdout.write(`\nScan of ${name}\n\nDECIMAL       HEXADECIMAL     DESCRIPTION\n${'-'.repeat(64)}\n`);
      for (let offset = 0; offset < bytes.length; offset++) {
        for (const sig of SIGNATURES) {
          if (sig.strictStart && offset > 0) continue;
          if (sig.magic.length < 3 && offset > 0) continue;
          if (matchesAt(bytes, sig.magic, offset)) {
            ctx.stdout.write(`${String(offset).padEnd(14)}0x${offset.toString(16).toUpperCase().padEnd(14)}${sig.label}\n`);
          }
        }
        if (bytes[offset] === 0x49 && matchesAt(bytes, [0x49, 0x45, 0x4e, 0x44], offset)) {
          ctx.stdout.write(`${String(offset + 8).padEnd(14)}0x${(offset + 8).toString(16).toUpperCase().padEnd(14)}End of PNG image data (IEND chunk ends here)\n`);
        }
      }
    }
  });

  c.exiftool = wrap((ctx) => {
    if (!ctx.args.length) throw new UsageError('missing file operand');
    for (const name of ctx.args) {
      const node = ctx.fs.lookup(ctx.resolve(name), ctx.user);
      const bytes = ctx.fs.readFile(ctx.resolve(name), ctx.user);
      const row = (key, value) => ctx.stdout.write(`${key.padEnd(32)}: ${value}\n`);
      row('File Name', basename(name));
      row('File Size', `${bytes.length} bytes`);
      row('File Modification Date/Time', new Date(node.mtime).toISOString().replace('T', ' ').slice(0, 19));
      row('File Type', describe(bytes).split(',')[0]);
      if (matchesAt(bytes, SIGNATURES[0].magic, 0)) {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 8;
        while (offset + 8 <= bytes.length) {
          const length = view.getUint32(offset);
          const type = text(bytes.subarray(offset + 4, offset + 8));
          const body = bytes.subarray(offset + 8, offset + 8 + length);
          if (type === 'IHDR') {
            row('Image Width', view.getUint32(offset + 8));
            row('Image Height', view.getUint32(offset + 12));
          }
          if (type === 'tEXt' || type === 'iTXt') {
            const zero = body.indexOf(0);
            const key = text(body.subarray(0, zero));
            const value = type === 'tEXt' ? text(body.subarray(zero + 1)) : text(body.subarray(zero + 5)).replace(/^\0*/, '').split('\0').pop();
            row(key.replace(/(^|\s)\w/g, (m) => m.toUpperCase()), value);
          }
          if (type === 'IEND') {
            const trailing = bytes.length - (offset + 12);
            if (trailing > 0) row('Warning', `[minor] Trailer data after PNG IEND chunk (${trailing} bytes)`);
            break;
          }
          offset += 12 + length;
        }
      }
      if (matchesAt(bytes, SIGNATURES[3].magic, 0)) {
        // PDF metadata lives in the Info dictionary as /Key (value) pairs.
        const source = text(bytes);
        row('PDF Version', /^%PDF-(\d\.\d)/.exec(source)?.[1] ?? 'unknown');
        const pdfDate = (v) => v.replace(/^D:(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d).*$/, '$1:$2:$3 $4:$5:$6');
        const keys = [['Title', 'Title'], ['Author', 'Author'], ['Subject', 'Subject'], ['Creator', 'Creator'], ['Producer', 'Producer'], ['CreationDate', 'Create Date'], ['ModDate', 'Modify Date']];
        for (const [key, label] of keys) {
          const m = new RegExp(`/${key}\\s*\\(([^)]*)\\)`).exec(source);
          if (m) row(label, key.endsWith('Date') ? pdfDate(m[1]) : m[1]);
        }
      }
    }
  });

  const offline = wrap((ctx) => {
    ctx.stderr.write(`${ctx.name}: this workspace has no network access. Everything you need is already on this machine.\n`);
    return 1;
  });
  for (const name of ['ping', 'curl', 'wget', 'ssh', 'nc', 'netcat', 'nmap', 'apt', 'apt-get', 'pip', 'git']) c[name] = offline;
  const missing = (message) => wrap((ctx) => {
    ctx.stderr.write(`${ctx.name}: ${message}\n`);
    return 127;
  });
  for (const name of ['nano', 'vim', 'vi', 'emacs']) c[name] = missing('there is no text editor here. Write files with echo "text" > file, or append with >>.');
  for (const name of ['python', 'python3', 'node', 'perl', 'gcc']) c[name] = missing('not installed in this workspace. Everything here can be solved with the shell tools. Type help to see them.');

  c.bash = c.sh = wrap((ctx) => {
    const [script, ...rest] = ctx.args;
    if (!script) return ctx.err('this shell is already running. Run a script with: bash script.sh');
    if (script === '-c') return ctx.shell.runLine(rest.join(' '), { stdout: ctx.stdout, stderr: ctx.stderr, isTTY: ctx.isTTY });
    return ctx.shell.runScript(ctx.resolve(script), rest, { stdin: ctx.stdin, stdout: ctx.stdout, stderr: ctx.stderr, isTTY: ctx.isTTY });
  });
  c.source = wrap((ctx) => ctx.shell.runScript(ctx.resolve(ctx.args[0] ?? ''), ctx.args.slice(1), { stdout: ctx.stdout, stderr: ctx.stderr, isTTY: ctx.isTTY }));

  c.basename = wrap((ctx) => ctx.stdout.write(basename(ctx.args[0] ?? '') + '\n'));
  c.dirname = wrap((ctx) => ctx.stdout.write(dirname(ctx.args[0] ?? '') + '\n'));
  c.seq = wrap((ctx) => {
    const nums = ctx.args.map(Number);
    const [start, step, end] = nums.length === 1 ? [1, 1, nums[0]] : nums.length === 2 ? [nums[0], 1, nums[1]] : nums;
    const out = [];
    for (let i = start; step > 0 ? i <= end : i >= end; i += step) {
      out.push(i);
      if (out.length > 10000) break;
    }
    ctx.stdout.write(out.join('\n') + (out.length ? '\n' : ''));
  });
  c.nl = wrap((ctx) => {
    let n = 1;
    for (const { bytes } of inputs(ctx, ctx.args)) for (const line of lines(bytes)) ctx.stdout.write(line.trim() ? `${String(n++).padStart(6)}\t${line}\n` : '\n');
  });

  return c;
}

function relative(path, root, ctx) {
  const start = ctx.resolve(root);
  if (path === start) return root;
  const rest = path.slice(start === '/' ? 1 : start.length + 1);
  return root === '/' ? `/${rest}` : `${root.replace(/\/+$/, '')}/${rest}`;
}

function groupId(fs, name) {
  const lines = text(fs.readFile('/etc/group', 'root')).split('\n');
  const line = lines.find((l) => l.startsWith(name + ':'));
  return line ? line.split(':')[2] : '1000';
}

function unescape(value) {
  return value.replace(/\\(x[0-9a-fA-F]{2}|[ntr0\\abe])/g, (_, code) => {
    if (code[0] === 'x') return String.fromCharCode(parseInt(code.slice(1), 16));
    return { n: '\n', t: '\t', r: '\r', 0: '\0', '\\': '\\', a: '\x07', b: '\b', e: '\x1b' }[code];
  });
}

// printf can produce raw bytes through \xNN escapes; keep them as bytes.
function latin1Safe(value) {
  if (!/[\u0080-\u00ff]/.test(value)) return value;
  return Uint8Array.from(value, (ch) => ch.charCodeAt(0) & 0xff);
}

export { describe as describeBytes, SIGNATURES };
export const COMMAND_NAMES = Object.keys(createCommands());
