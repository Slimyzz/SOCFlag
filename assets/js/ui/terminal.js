// A lightweight terminal for the practice shell: a scrollback, a real <input>
// for the current line (so mobile keyboards and screen readers work), history,
// tab completion and basic ANSI colours.
import { h, fill } from '../core/dom.js';

const SGR_CLASSES = { 1: 'b', 31: 'red', 32: 'green', 33: 'yellow', 34: 'blue', 35: 'magenta', 36: 'cyan' };

function renderAnsi(target, value, stream) {
  const parts = value.split(/\x1b\[([0-9;]*)m/);
  let classes = [];
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      const codes = part.split(';').filter(Boolean).map(Number);
      if (!codes.length || codes.includes(0)) classes = [];
      for (const code of codes) if (SGR_CLASSES[code]) classes.push(SGR_CLASSES[code]);
      return;
    }
    if (!part) return;
    // Show unprintable bytes the way a terminal would: as replacement marks.
    const clean = part.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '�');
    const cls = [...classes, stream === 'err' ? 'err' : ''].filter(Boolean).join(' ');
    target.append(cls ? h('span', { class: cls }, clean) : document.createTextNode(clean));
  });
}

export function mountTerminal(container, machine, { motd = '', onRun } = {}) {
  const { shell } = machine;
  const output = h('div', { class: 'term-output', role: 'log', 'aria-live': 'polite', 'aria-label': 'Terminal output' });
  const promptEl = h('span', { class: 'term-prompt', 'aria-hidden': 'true' });
  const input = h('input', {
    class: 'term-input',
    type: 'text',
    autocomplete: 'off',
    autocapitalize: 'off',
    autocorrect: 'off',
    spellcheck: 'false',
    'aria-label': 'Type a command and press Enter'
  });
  const line = h('form', { class: 'term-line' }, promptEl, input);
  const screen = h('div', { class: 'term' }, output, line);
  fill(container, screen);

  let historyIndex = shell.history.length;
  let draft = '';

  const renderPrompt = (target) => {
    const p = shell.prompt();
    fill(target, 
      h('span', { class: 'p-user' }, `${p.user}@${p.host}`), ':',
      h('span', { class: 'p-cwd' }, p.cwd), `${p.symbol} `
    );
  };

  const write = (value, stream = 'out') => {
    const block = h('span', { class: 'chunk' });
    renderAnsi(block, value, stream);
    output.append(block);
  };

  const scroll = () => {
    screen.scrollTop = screen.scrollHeight;
  };

  if (motd) write(motd.endsWith('\n') ? motd : motd + '\n');
  renderPrompt(promptEl);

  const run = (command) => {
    const echo = h('div', { class: 'term-echo' });
    renderPrompt(echo);
    echo.append(h('span', { class: 'cmd' }, command));
    output.append(echo);
    const result = shell.execute(command);
    for (const chunk of result.chunks) {
      if (chunk.text.includes('\x1b[2J')) {
        output.replaceChildren();
        continue;
      }
      write(chunk.text, chunk.stream);
    }
    // Make sure the next prompt starts on a fresh line, as Bash does.
    const last = output.lastChild?.textContent ?? '';
    if (result.chunks.length && last && !last.endsWith('\n')) output.append(document.createTextNode('\n'));
    renderPrompt(promptEl);
    historyIndex = shell.history.length;
    scroll();
    onRun?.(command, result);
  };

  line.addEventListener('submit', (event) => {
    event.preventDefault();
    const command = input.value;
    input.value = '';
    run(command);
  });

  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      if (historyIndex === shell.history.length) draft = input.value;
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = shell.history[historyIndex] ?? '';
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      historyIndex = Math.min(shell.history.length, historyIndex + 1);
      input.value = historyIndex === shell.history.length ? draft : shell.history[historyIndex];
    } else if (event.key === 'Tab') {
      event.preventDefault();
      complete();
    } else if (event.key === 'l' && event.ctrlKey) {
      event.preventDefault();
      output.replaceChildren();
    } else if (event.key === 'c' && event.ctrlKey && !window.getSelection()?.toString()) {
      event.preventDefault();
      const echo = h('div', { class: 'term-echo' });
      renderPrompt(echo);
      echo.append(h('span', { class: 'cmd' }, input.value + '^C'));
      output.append(echo);
      input.value = '';
      scroll();
    }
  });

  // Completes a command name for the first word, otherwise a path.
  function complete() {
    const value = input.value.slice(0, input.selectionStart ?? input.value.length);
    const tail = input.value.slice(value.length);
    const words = value.split(/\s+/);
    const current = words[words.length - 1];
    let options;
    let prefix = current;
    if (words.length === 1) {
      options = Object.keys(shell.commands).filter((name) => name.startsWith(current)).map((name) => name + ' ');
    } else {
      const slash = current.lastIndexOf('/');
      const dirPart = slash >= 0 ? current.slice(0, slash + 1) : '';
      prefix = current.slice(slash + 1);
      const dir = shell.resolve(dirPart.replace(/^~/, shell.vars.HOME) || '.');
      try {
        options = shell.fs.list(dir, shell.user)
          .filter((node) => node.name.startsWith(prefix) && (prefix.startsWith('.') || !node.name.startsWith('.')))
          .map((node) => node.name + (node.type === 'dir' ? '/' : ' '));
      } catch {
        options = [];
      }
    }
    if (!options.length) return;
    if (options.length === 1) {
      input.value = value + options[0].slice(prefix.length) + tail;
      return;
    }
    let common = options[0];
    for (const option of options) while (!option.startsWith(common)) common = common.slice(0, -1);
    if (common.length > prefix.length) {
      input.value = value + common.slice(prefix.length) + tail;
      return;
    }
    const echo = h('div', { class: 'term-echo' });
    renderPrompt(echo);
    echo.append(h('span', { class: 'cmd' }, input.value));
    output.append(echo);
    write(options.map((o) => o.trim()).join('  ') + '\n');
    scroll();
  }

  screen.addEventListener('click', () => {
    if (!window.getSelection()?.toString()) input.focus({ preventScroll: true });
  });

  return {
    focus: () => input.focus({ preventScroll: true }),
    run,
    type(command) {
      input.value = command;
      input.focus({ preventScroll: true });
    }
  };
}
