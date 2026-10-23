// Renders lesson content. Each graded block reports back once it is answered
// correctly so the lesson knows when it is complete. Teaching formats:
//   text, example (worked transcript), code, table, note, reveal, timeline,
//   quiz (multiple choice with feedback per option), predict (read code or a
//   command, then predict the result), answer (type a short answer),
//   order (put steps in order), spot (click the vulnerable line),
//   task (do something real in the workspace beside the lesson).
import { h, md, mdNode, inline, escapeHtml } from '../core/dom.js';
import { store } from '../core/store.js';

const LETTERS = 'ABCDEFGH';
const GRADED = new Set(['quiz', 'predict', 'answer', 'order', 'spot', 'task']);

export function isGraded(block) {
  return GRADED.has(block.type);
}

export function blockId(lessonId, block, index) {
  return block.id ? `${lessonId}:${block.id}` : `${lessonId}:${index}`;
}

function codeBlock(source, { numbered = false } = {}) {
  const lines = String(source).replace(/\n$/, '').split('\n');
  const pre = h('pre', { class: 'code' });
  pre.innerHTML = lines.map((line, i) => (numbered ? `<span class="ln">${i + 1}</span>` : '') + escapeHtml(line)).join('\n');
  return pre;
}

function shell(kind, question, ...body) {
  return h('div', { class: 'check' },
    h('p', { class: 'check-kind' }, kind),
    h('div', { class: 'check-q', html: md(question) }),
    ...body);
}

function markDone(card, id, ctx, fresh) {
  card.classList.add('done');
  if (fresh) {
    card.classList.add('just-done');
    store.answer(id);
    ctx.onSolved?.(id);
  }
}

function choice(block, id, ctx, kind) {
  const already = store.answered(id);
  const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
  const buttons = block.options.map((option, i) => {
    const text = typeof option === 'string' ? option : option.text;
    return h('button', { class: 'option', type: 'button', html: `<span class="key">${LETTERS[i]}</span><span>${inline(text)}</span>` });
  });
  const correctIndex = block.options.findIndex((o) => o.correct);
  const card = shell(kind, block.question, ...(block.code ? [codeBlock(block.code)] : []), h('div', { class: 'options' }, buttons), feedback);

  const finish = (fresh) => {
    buttons.forEach((b, i) => {
      b.disabled = true;
      if (i === correctIndex) b.classList.add('is-right');
    });
    const explain = block.options[correctIndex].why ?? block.explain;
    feedback.className = 'feedback ok';
    feedback.innerHTML = `<p><strong>${fresh ? 'Correct.' : 'Answered.'}</strong></p>${explain ? `<div class="explain">${md(explain)}</div>` : ''}`;
    markDone(card, id, ctx, fresh);
  };

  buttons.forEach((button, i) => {
    button.addEventListener('click', () => {
      if (i === correctIndex) return finish(true);
      button.classList.add('is-wrong');
      button.disabled = true;
      const why = block.options[i].why;
      feedback.className = 'feedback no';
      feedback.innerHTML = `<p><strong>Not quite.</strong></p>${why ? `<div class="explain">${md(why)}</div>` : '<p class="explain">Try another option.</p>'}`;
    });
  });
  if (already) finish(false);
  return card;
}

function answer(block, id, ctx) {
  const already = store.answered(id);
  const input = h('input', { class: 'field mono', type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Your answer' });
  const button = h('button', { class: 'btn', type: 'submit' }, 'Check');
  const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
  const form = h('form', { class: 'row' }, h('div', { style: 'flex:1;min-width:12rem' }, input), button);
  const card = shell('Your turn', block.question, form, feedback);
  const normalise = (v) => String(v).trim().replace(/\s+/g, ' ').toLowerCase();
  const accepted = block.accept.map(normalise);
  let attempts = 0;

  const finish = (fresh) => {
    input.value = block.accept[0];
    input.disabled = true;
    button.disabled = true;
    feedback.className = 'feedback ok';
    feedback.innerHTML = `<p><strong>${fresh ? 'Correct.' : 'Answered.'}</strong></p>${block.explain ? `<div class="explain">${md(block.explain)}</div>` : ''}`;
    markDone(card, id, ctx, fresh);
  };
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!input.value.trim()) return;
    if (accepted.includes(normalise(input.value))) return finish(true);
    attempts++;
    feedback.className = 'feedback no';
    const hint = attempts >= 2 && block.hint ? `<div class="explain">${md(block.hint)}</div>` : '';
    feedback.innerHTML = `<p><strong>Not that one.</strong> ${attempts < 2 && block.hint ? 'Try again, or have another go for a hint.' : ''}</p>${hint}`;
    if (attempts >= 4) {
      feedback.innerHTML += `<p class="explain">The answer is <code>${escapeHtml(block.accept[0])}</code>. Type it in to continue.</p>`;
    }
  });
  if (already) finish(false);
  return card;
}

function order(block, id, ctx) {
  const already = store.answered(id);
  const correct = block.items;
  // Deterministic shuffle so the list is scrambled the same way on every visit.
  let items = correct.map((text, i) => ({ text, key: i }));
  items = items.map((item, i) => ({ item, sort: (i * 7 + 3) % items.length })).sort((a, b) => a.sort - b.sort).map((x) => x.item);
  if (items.every((item, i) => item.key === i)) items.reverse();
  const list = h('ol', { class: 'order-list' });
  const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
  const checkButton = h('button', { class: 'btn', type: 'button' }, 'Check order');
  const card = shell('Put in order', block.question, list, h('div', { class: 'row', style: 'margin-top:.75rem' }, checkButton), feedback);
  let locked = false;

  const render = () => {
    list.replaceChildren(...items.map((item, i) => h('li', {},
      h('span', { html: inline(item.text) }),
      locked ? null : h('span', { class: 'moves' },
        h('button', { class: 'btn small', type: 'button', disabled: i === 0, 'aria-label': `Move "${item.text}" up`, onclick: () => move(i, -1) }, 'Up'),
        h('button', { class: 'btn small', type: 'button', disabled: i === items.length - 1, 'aria-label': `Move "${item.text}" down`, onclick: () => move(i, 1) }, 'Down'))
    )));
  };
  const move = (i, delta) => {
    [items[i], items[i + delta]] = [items[i + delta], items[i]];
    render();
    list.querySelectorAll('li')[i + delta]?.querySelector('button')?.focus();
  };
  const finish = (fresh) => {
    items = correct.map((text, i) => ({ text, key: i }));
    locked = true;
    render();
    checkButton.remove();
    feedback.className = 'feedback ok';
    feedback.innerHTML = `<p><strong>${fresh ? 'That is the right order.' : 'Answered.'}</strong></p>${block.explain ? `<div class="explain">${md(block.explain)}</div>` : ''}`;
    markDone(card, id, ctx, fresh);
  };
  checkButton.addEventListener('click', () => {
    const right = items.filter((item, i) => item.key === i).length;
    if (right === items.length) return finish(true);
    feedback.className = 'feedback no';
    feedback.innerHTML = `<p><strong>${right} of ${items.length} are in the right place.</strong> Keep moving them.</p>`;
  });
  if (already) finish(false);
  else render();
  return card;
}

function spot(block, id, ctx) {
  const already = store.answered(id);
  const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
  const lines = block.code.replace(/\n$/, '').split('\n');
  const buttons = lines.map((line, i) => h('button', { type: 'button', html: `<span class="ln">${i + 1}</span>${escapeHtml(line) || ' '}`, 'aria-label': `Line ${i + 1}: ${line.trim() || 'blank'}` }));
  const card = shell('Spot the problem', block.question, h('div', { class: 'spot' }, buttons), feedback);
  const answerLines = [].concat(block.line).map((n) => n - 1);
  const finish = (fresh) => {
    buttons.forEach((b, i) => {
      b.disabled = true;
      if (answerLines.includes(i)) b.classList.add('is-right');
    });
    feedback.className = 'feedback ok';
    feedback.innerHTML = `<p><strong>${fresh ? 'Found it.' : 'Answered.'}</strong></p><div class="explain">${md(block.explain)}</div>`;
    markDone(card, id, ctx, fresh);
  };
  buttons.forEach((button, i) => button.addEventListener('click', () => {
    if (answerLines.includes(i)) return finish(true);
    button.classList.add('is-wrong');
    feedback.className = 'feedback no';
    feedback.innerHTML = `<p><strong>Line ${i + 1} is fine.</strong> ${block.nudge ? inline(block.nudge) : 'Look for where untrusted input is used.'}</p>`;
  }));
  if (already) finish(false);
  return card;
}

function task(block, id, ctx) {
  const already = store.answered(id);
  const box = h('span', { class: 'box', 'aria-hidden': 'true' });
  const hintLine = block.hint ? h('p', { class: 'hintline', html: `Stuck? ${inline(block.hint)}` }) : null;
  const card = h('div', { class: 'task', role: 'group', 'aria-label': 'Try it in the workspace' }, box, h('div', {}, h('div', { class: 'prose', html: md(block.text) }), hintLine));
  const done = (fresh) => {
    card.classList.add('done');
    box.textContent = '✓';
    card.setAttribute('aria-label', 'Completed task');
    if (fresh) {
      store.answer(id);
      ctx.onSolved?.(id);
    }
  };
  if (already) done(false);
  else ctx.watch?.((log, machine) => {
    if (card.classList.contains('done')) return;
    try {
      if (block.check(log, machine)) done(true);
    } catch {}
  });
  return card;
}

function example(block, ctx) {
  const steps = block.steps.map((step) => {
    const pre = h('pre');
    if (step.cmd) pre.append(h('span', { class: 'cmd' }, step.cmd), '\n');
    if (step.out) pre.append(h('span', { class: 'out' }, step.out.replace(/\n$/, '')));
    const tryButton = step.cmd && ctx.tryIt ? h('button', { class: 'btn small try', type: 'button', onclick: () => ctx.tryIt(step.cmd) }, ctx.tryLabel) : null;
    return h('div', { class: 'example-step' }, pre, step.note ? h('div', { class: 'why' }, tryButton, h('span', { html: inline(step.note) })) : tryButton ? h('div', { class: 'why' }, tryButton) : null);
  });
  return h('div', { class: 'example' }, h('div', { class: 'example-head' }, h('span', {}, block.title ?? 'Worked example')), steps);
}

export function renderBlock(block, index, ctx) {
  const id = blockId(ctx.lessonId, block, index);
  switch (block.type) {
    case 'heading':
      return h('h2', {}, block.text);
    case 'text':
      return mdNode(block.body);
    case 'example':
      return example(block, ctx);
    case 'code':
      return h('figure', { style: 'margin:0' }, codeBlock(block.body, { numbered: block.numbered }), block.caption ? h('figcaption', { class: 'caption', html: inline(block.caption) }) : null);
    case 'table':
      return h('div', { class: 'table-scroll' }, h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, block.head.map((cell) => h('th', { html: inline(cell) })))),
        h('tbody', {}, block.rows.map((row) => h('tr', {}, row.map((cell) => h('td', { html: inline(cell) })))))));
    case 'note':
      return h('div', { class: 'note', dataset: { tone: block.tone ?? 'tip' } }, block.title ? h('strong', {}, block.title) : null, h('div', { html: md(block.body) }));
    case 'timeline':
      return h('ol', { class: 'timeline' }, block.items.map(([when, what]) => h('li', {}, h('time', {}, when), h('span', { html: inline(what) }))));
    case 'reveal':
      return h('details', { class: 'reveal' }, h('summary', {}, block.title), mdNode(block.body));
    case 'quiz':
      return choice(block, id, ctx, 'Check your understanding');
    case 'predict':
      return choice(block, id, ctx, 'Predict the result');
    case 'answer':
      return answer(block, id, ctx);
    case 'order':
      return order(block, id, ctx);
    case 'spot':
      return spot(block, id, ctx);
    case 'task':
      return task(block, id, ctx);
    default:
      return h('p', {}, `Unknown block type: ${block.type}`);
  }
}

export function renderTerms(terms) {
  if (!terms?.length) return null;
  const def = h('div', { class: 'term-def', hidden: true, 'aria-live': 'polite' });
  let open = null;
  const chips = terms.map(([term, definition]) => {
    const chip = h('button', { class: 'term-chip', type: 'button', 'aria-expanded': 'false' }, term);
    chip.addEventListener('click', () => {
      const same = open === chip;
      open?.setAttribute('aria-expanded', 'false');
      if (same) {
        open = null;
        def.hidden = true;
        return;
      }
      open = chip;
      chip.setAttribute('aria-expanded', 'true');
      def.hidden = false;
      def.innerHTML = `<strong>${escapeHtml(term)}</strong>. ${inline(definition)}`;
    });
    return h('li', {}, chip);
  });
  return h('div', { class: 'lesson-block' }, h('ul', { class: 'terms', 'aria-label': 'Key terms in this lesson' }, chips), def);
}
