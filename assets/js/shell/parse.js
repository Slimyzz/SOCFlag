// Turns a command line into a small syntax tree:
//   line     := pipeline (( ';' | '&&' | '||' ) pipeline)*
//   pipeline := command ('|' command)*
//   command  := word* with redirections mixed in
// Words keep their quoting so expansion can follow Bash rules: variables
// expand inside double quotes, globs only expand outside quotes.

export class ParseError extends Error {}

const OPERATORS = ['&&', '||', '2>>', '2>&1', '&>', '>>', '2>', '>', '<', '|', ';', '&'];

function readDollar(src, i, parts, quoted) {
  // i points at '$'
  const next = src[i + 1];
  if (next === '(') {
    let depth = 1, j = i + 2;
    while (j < src.length && depth) {
      if (src[j] === '(') depth++;
      else if (src[j] === ')') depth--;
      j++;
    }
    if (depth) throw new ParseError('unexpected end of input: missing )');
    parts.push({ kind: 'sub', value: src.slice(i + 2, j - 1), quoted });
    return j;
  }
  if (next === '{') {
    const end = src.indexOf('}', i);
    if (end < 0) throw new ParseError('bad substitution');
    parts.push({ kind: 'var', value: src.slice(i + 2, end), quoted });
    return end + 1;
  }
  const match = /^([A-Za-z_][A-Za-z0-9_]*|[?$#0-9@*])/.exec(src.slice(i + 1));
  if (!match) {
    parts.push({ kind: 'lit', value: '$', quoted });
    return i + 1;
  }
  parts.push({ kind: 'var', value: match[1], quoted });
  return i + 1 + match[1].length;
}

export function tokenize(src) {
  const tokens = [];
  let parts = null;
  const flush = () => {
    if (parts) tokens.push({ type: 'word', parts });
    parts = null;
  };
  const lit = (value, quoted) => {
    parts ??= [];
    const last = parts[parts.length - 1];
    if (last && last.kind === 'lit' && last.quoted === quoted) last.value += value;
    else parts.push({ kind: 'lit', value, quoted });
  };

  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\n') {
      flush();
      i++;
      continue;
    }
    if (ch === '#' && !parts) break;
    if (ch === '\\') {
      if (i + 1 < src.length) lit(src[i + 1], true);
      i += 2;
      continue;
    }
    if (ch === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) throw new ParseError("unexpected end of input: missing closing '");
      lit(src.slice(i + 1, end), true);
      if (end === i + 1) parts ??= [];
      i = end + 1;
      continue;
    }
    if (ch === '"') {
      lit('', true);
      let j = i + 1;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && '"\\$`'.includes(src[j + 1])) {
          lit(src[j + 1], true);
          j += 2;
        } else if (src[j] === '$') {
          j = readDollar(src, j, parts, true);
        } else {
          lit(src[j], true);
          j++;
        }
      }
      if (j >= src.length) throw new ParseError('unexpected end of input: missing closing "');
      i = j + 1;
      continue;
    }
    if (ch === '$') {
      parts ??= [];
      i = readDollar(src, i, parts, false);
      continue;
    }
    const op = OPERATORS.find((candidate) => src.startsWith(candidate, i));
    // "2>" only counts as a redirection when the 2 starts a word.
    if (op && (!op.startsWith('2') || !parts)) {
      flush();
      tokens.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }
    lit(ch, false);
    i++;
  }
  flush();
  return tokens;
}

export function parse(src) {
  const tokens = tokenize(src);
  const list = [];
  let pipeline = [];
  let command = { words: [], redirects: [] };
  let connector = null;

  const endCommand = () => {
    if (!command.words.length && !command.redirects.length) throw new ParseError('syntax error near unexpected token');
    pipeline.push(command);
    command = { words: [], redirects: [] };
  };
  const endPipeline = (next) => {
    endCommand();
    list.push({ connector, pipeline });
    pipeline = [];
    connector = next;
  };

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.type === 'word') {
      command.words.push(token);
      continue;
    }
    switch (token.value) {
      case '|':
        endCommand();
        break;
      case ';':
      case '&':
        if (command.words.length || command.redirects.length) endPipeline(';');
        break;
      case '&&':
      case '||':
        endPipeline(token.value);
        break;
      case '2>&1':
        command.redirects.push({ op: '2>&1' });
        break;
      default: {
        const target = tokens[i + 1];
        if (!target || target.type !== 'word') throw new ParseError(`syntax error near unexpected token \`${token.value}'`);
        command.redirects.push({ op: token.value, target });
        i++;
      }
    }
  }
  if (command.words.length || command.redirects.length) endPipeline(null);
  else if (pipeline.length || (connector && connector !== ';')) throw new ParseError('syntax error: unexpected end of line');
  return list;
}
