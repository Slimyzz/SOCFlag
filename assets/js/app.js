import { h, md, mdNode, inline, announce, escapeHtml } from './core/dom.js';
import { store, writePref } from './core/store.js';
import { unseal, normaliseFlag } from './lib/seal.js';
import { renderBlock, renderTerms, isGraded, blockId } from './ui/blocks.js';
import { mountWorkspace, TRY_LABELS } from './ui/workspace.js';
import { mountTerminal } from './ui/terminal.js';
import { createMachine } from './shell/index.js';
import { sections } from '../../content/index.js';

const main = document.getElementById('main');
const LEVELS = { easy: 'Easy', medium: 'Medium', hard: 'Hard' };

// Lookups built once from the content tree.
const lessons = new Map();
const challenges = new Map();
for (const section of sections) {
  section.lessons.forEach((lesson, index) => lessons.set(lesson.id, { ...lesson, section, index }));
  section.challenges.forEach((challenge, index) => challenges.set(challenge.id, { ...challenge, section, index }));
}
const allChallenges = [...challenges.values()];
const totalPoints = allChallenges.reduce((sum, c) => sum + c.points, 0);

function level(value) {
  return h('span', { class: 'level', dataset: { level: value } }, h('i', { 'aria-hidden': 'true' }, h('b'), h('b'), h('b')), LEVELS[value]);
}

function tick() {
  return h('svg', { class: 'tick', viewBox: '0 0 16 16', 'aria-hidden': 'true', html: '<path d="M3 8.5l3.2 3L13 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' });
}

function sectionProgress(section) {
  const doneLessons = section.lessons.filter((l) => store.lessonDone(l.id)).length;
  const solved = section.challenges.filter((c) => store.solved(c.id)).length;
  const total = section.lessons.length + section.challenges.length;
  return { doneLessons, solved, ratio: total ? (doneLessons + solved) / total : 0 };
}

function earnedPoints() {
  return allChallenges.filter((c) => store.solved(c.id)).reduce((sum, c) => sum + c.points, 0);
}

function updateScore() {
  const score = document.getElementById('score');
  const points = earnedPoints();
  score.replaceChildren(...(points ? [h('strong', {}, String(points)), ' points'] : []));
}

function nextStep() {
  for (const section of sections) {
    for (const lesson of section.lessons) if (!store.lessonDone(lesson.id)) return { kind: 'lesson', item: lessons.get(lesson.id) };
    for (const challenge of section.challenges) if (!store.solved(challenge.id)) return { kind: 'challenge', item: challenges.get(challenge.id) };
  }
  return null;
}

function setTitle(title) {
  document.title = title ? `${title} | HiddenWell` : 'HiddenWell: learn cybersecurity by doing it';
}

// ---------------------------------------------------------------- Home

function homeDemo() {
  const machine = createMachine({
    hostname: 'lab',
    files: {
      '/home/learner/readme.txt': 'Someone left a note in this folder, but ls does not show it.\nNames that start with a dot are hidden from a normal listing.\n',
      '/home/learner/reports/': {},
      '/home/learner/reports/monday.txt': 'Nothing unusual today.\n',
      '/home/learner/.note': 'You found it. Hidden files are just files whose names start with a dot.\nThat is lesson 3 of Linux fundamentals, and you have already done it.\n'
    }
  });
  const status = h('span', {}, 'Type ', h('strong', {}, 'ls'), ' and press Enter');
  const task = h('div', { class: 'demo-task' }, h('span', {}, 'Find the hidden note'), status);
  const screen = h('div');
  const steps = [
    { test: (c) => /^ls\b/.test(c) && !/-\w*a/.test(c), next: () => status.replaceChildren('Now read ', h('strong', {}, 'readme.txt'), ' with cat') },
    { test: (c) => /^cat\b.*readme/.test(c), next: () => status.replaceChildren('Try ', h('strong', {}, 'ls -a')) },
    { test: (c) => /^ls\b.*-\w*a/.test(c), next: () => status.replaceChildren('Read it: ', h('strong', {}, 'cat .note')) },
    { test: (c) => /^cat\b.*\.note/.test(c), next: () => status.replaceChildren(h('span', { class: 'done' }, 'Found it')) }
  ];
  let step = 0;
  mountTerminal(screen, machine, {
    motd: 'This is a real shell running in your browser. Nothing you type leaves this page.\n',
    onRun: (command) => {
      const trimmed = command.trim();
      // Let people skip ahead: any later step that matches moves the guide along.
      for (let i = step; i < steps.length; i++) {
        if (steps[i].test(trimmed)) {
          steps[i].next();
          step = i + 1;
          break;
        }
      }
    }
  });
  return h('div', { class: 'demo' }, task, screen);
}

function trackList() {
  return h('div', { class: 'tracks' }, sections.map((section, i) => {
    const p = sectionProgress(section);
    return h('a', { class: 'track', href: `#/learn/${section.id}` },
      h('span', { class: 'track-index' }, String(i + 1)),
      h('span', { class: 'track-name' }, section.title, h('small', {}, `${section.lessons.length} lessons, ${section.challenges.length} challenges`)),
      h('p', {}, section.summary),
      h('span', { class: 'track-progress' },
        p.ratio ? `${p.doneLessons} of ${section.lessons.length} lessons, ${p.solved} of ${section.challenges.length} solved` : 'Not started',
        h('div', { class: 'bar', 'aria-hidden': 'true' }, h('span', { style: `width:${Math.round(p.ratio * 100)}%` }))));
  }));
}

function viewHome() {
  setTitle();
  const next = nextStep();
  const started = Object.keys(store.get().lessons).length || Object.keys(store.get().solved).length;
  const cta = next
    ? h('a', { class: 'btn primary', href: next.kind === 'lesson' ? `#/lesson/${next.item.id}` : `#/challenge/${next.item.id}` }, started ? `Continue: ${next.item.title}` : 'Start the first lesson')
    : h('a', { class: 'btn primary', href: '#/challenges' }, 'See every challenge');
  const lessonCount = lessons.size, challengeCount = challenges.size;

  return [
    h('section', { class: 'hero' },
      h('div', {},
        h('h1', {}, 'Learn to investigate like a defender.'),
        h('p', { class: 'hero-lead' }, `${lessonCount} short lessons and ${challengeCount} capture-the-flag challenges in blue-team security: logs, email, files and network traffic. Every lab runs inside your browser, so there is nothing to install and nothing to sign up for.`),
        h('div', { class: 'row' }, cta, h('a', { class: 'btn', href: '#/challenges' }, 'Browse challenges')),
        h('p', { class: 'hero-note' }, 'Your progress stays in this browser. No account, no tracking.')),
      homeDemo()),
    h('ol', { class: 'method', 'aria-label': 'How each topic works' },
      h('li', {}, h('h3', {}, 'Read a little'), h('p', {}, 'Each lesson explains one idea with a worked example you can type along with.')),
      h('li', {}, h('h3', {}, 'Check yourself'), h('p', {}, 'Predict the output, spot the bug, put the steps in order. Wrong answers explain why.')),
      h('li', {}, h('h3', {}, 'Do it for real'), h('p', {}, 'Work in a live terminal, a SIEM, a mailbox or a packet capture, on evidence that behaves like the real thing.')),
      h('li', {}, h('h3', {}, 'Capture the flag'), h('p', {}, 'Investigate on your own, with hints if you need them and a write-up after that explains how and why.'))),
    h('div', { class: 'block-head' }, h('h2', {}, 'Topics'), h('p', {}, 'Work through them in order, or jump to what you need.')),
    trackList()
  ];
}

// ---------------------------------------------------------------- Learn

function viewLearn() {
  setTitle('Learn');
  return [
    h('header', { class: 'page-head' }, h('h1', {}, 'Learn'), h('p', { class: 'lede' }, `${sections.length} topics, each a sequence of short lessons followed by challenges. Linux comes first because most other topics build on the terminal, and the incident response capstone comes last because it draws on all of them.`)),
    trackList()
  ];
}

function viewSection(id) {
  const section = sections.find((s) => s.id === id);
  if (!section) return notFound();
  setTitle(section.title);
  const p = sectionProgress(section);
  const lessonItems = section.lessons.map((lesson, i) => {
    const done = store.lessonDone(lesson.id);
    return h('li', { class: done ? 'seq-done' : '' }, h('a', { href: `#/lesson/${lesson.id}` },
      h('span', { class: 'seq-num' }, done ? tick() : String(i + 1)),
      h('span', {}, h('span', { class: 'seq-title' }, lesson.title), h('span', { class: 'seq-sub' }, lesson.summary)),
      h('span', { class: 'seq-meta' }, `${lesson.minutes} min`)));
  });
  const challengeItems = section.challenges.map((challenge) => {
    const solved = store.solved(challenge.id);
    return h('li', { class: solved ? 'seq-done' : '' }, h('a', { href: `#/challenge/${challenge.id}` },
      h('span', { class: 'seq-num' }, solved ? tick() : ''),
      h('span', {}, h('span', { class: 'seq-title' }, challenge.title), h('span', { class: 'seq-sub' }, challenge.goal)),
      h('span', { class: 'seq-meta' }, level(challenge.difficulty), h('br'), `${challenge.points} points`)));
  });
  const next = section.lessons.find((l) => !store.lessonDone(l.id)) ?? null;
  const nextChallenge = section.challenges.find((c) => !store.solved(c.id)) ?? null;
  return [
    h('header', { class: 'page-head' },
      h('p', { class: 'crumbs' }, h('a', { href: '#/learn' }, 'Learn')),
      h('h1', {}, section.title),
      h('p', { class: 'lede' }, section.intro),
      h('div', { class: 'facts' },
        h('span', {}, h('strong', {}, `${p.doneLessons}/${section.lessons.length}`), ' lessons done'),
        h('span', {}, h('strong', {}, `${p.solved}/${section.challenges.length}`), ' challenges solved'),
        h('span', {}, `About ${section.lessons.reduce((s, l) => s + l.minutes, 0)} minutes of lessons`))),
    h('div', { class: 'section-grid' },
      h('div', {},
        h('h2', { class: 'subhead', style: 'margin-top:0' }, 'Lessons'),
        h('ol', { class: 'sequence' }, lessonItems),
        h('h2', { class: 'subhead' }, 'Challenges'),
        h('p', { class: 'muted small' }, 'Ordered from easiest. Each one says which lessons help.'),
        h('ul', { class: 'sequence' }, challengeItems)),
      h('aside', { class: 'outcomes' },
        h('h2', {}, 'By the end you can'),
        h('ul', {}, section.outcomes.map((o) => h('li', {}, o))),
        next ? h('a', { class: 'btn primary', href: `#/lesson/${next.id}` }, p.doneLessons ? 'Next lesson' : 'Start lesson 1')
          : nextChallenge ? h('a', { class: 'btn primary', href: `#/challenge/${nextChallenge.id}` }, 'Next challenge')
            : h('p', { class: 'muted small', style: 'margin:0' }, 'You have finished this topic.')))
  ];
}

// ---------------------------------------------------------------- Lesson

let activeWorkspace = null;

async function viewLesson(id) {
  const lesson = lessons.get(id);
  if (!lesson) return notFound();
  setTitle(lesson.title);
  store.open(id);
  const { section, index } = lesson;
  const graded = lesson.blocks.map((block, i) => ({ block, id: blockId(lesson.id, block, i) })).filter((x) => isGraded(x.block));
  const remaining = () => graded.filter((g) => !store.answered(g.id)).length;
  const counter = h('span', {});
  const watchers = [];
  const sideHost = h('div', { class: 'activity-side' });
  const nextLesson = section.lessons[index + 1];
  const endBox = h('section', { class: 'lesson-end', 'aria-live': 'polite' });

  const refresh = () => {
    const left = remaining();
    counter.textContent = graded.length ? (left ? `${graded.length - left} of ${graded.length} checks done` : 'All checks done') : '';
    if (!left && graded.length) complete();
    renderEnd();
  };
  const complete = () => {
    if (store.lessonDone(lesson.id)) return;
    store.completeLesson(lesson.id);
    for (const [term] of lesson.terms ?? []) store.seedCard(`${lesson.id}::${term}`);
    announce('Lesson complete.');
  };
  const renderEnd = () => {
    const done = store.lessonDone(lesson.id);
    const forward = nextLesson
      ? h('a', { class: `btn ${done ? 'primary' : ''}`, href: `#/lesson/${nextLesson.id}` }, `Next lesson: ${nextLesson.title}`)
      : section.challenges[0] ? h('a', { class: `btn ${done ? 'primary' : ''}`, href: `#/challenge/${section.challenges[0].id}` }, 'Start the challenges') : null;
    const related = section.challenges.filter((c) => (c.prepare ?? []).includes(lesson.id) && !store.solved(c.id));
    if (done) {
      endBox.replaceChildren(
        h('h2', {}, 'Lesson complete'),
        h('p', { class: 'muted' }, lesson.terms?.length ? `Its ${lesson.terms.length} key terms are now in your review deck.` : 'Nice work.'),
        related.length ? h('p', {}, 'Ready for a challenge on this? ', ...related.slice(0, 2).flatMap((c, i) => [i ? ' or ' : '', h('a', { href: `#/challenge/${c.id}` }, c.title)])) : null,
        h('div', { class: 'row' }, forward, h('a', { class: 'btn quiet', href: `#/learn/${section.id}` }, 'Back to topic')));
    } else if (!graded.length) {
      endBox.replaceChildren(h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'button', onclick: () => { complete(); refresh(); updateScore(); } }, 'Mark as done'), forward));
    } else {
      const left = remaining();
      endBox.replaceChildren(h('p', { class: 'muted' }, `${left} ${left === 1 ? 'check' : 'checks'} left in this lesson. Answer them to finish it.`), h('div', { class: 'row' }, forward));
    }
  };

  const ctx = {
    lessonId: lesson.id,
    onSolved: () => refresh(),
    watch: (fn) => watchers.push(fn),
    tryIt: TRY_LABELS[lesson.workspace?.type] ? (command) => activeWorkspace?.tryIt(command) : null,
    tryLabel: TRY_LABELS[lesson.workspace?.type]
  };
  const content = h('div', { class: 'activity-main' },
    h('header', { class: 'activity-head' },
      h('p', { class: 'crumbs' }, h('a', { href: '#/learn' }, 'Learn'), ' / ', h('a', { href: `#/learn/${section.id}` }, section.title)),
      h('h1', {}, lesson.title),
      h('div', { class: 'facts' }, h('span', {}, `Lesson ${index + 1} of ${section.lessons.length}`), h('span', {}, `About ${lesson.minutes} minutes`), counter)),
    renderTerms(lesson.terms),
    lesson.blocks.map((block, i) => h('div', { class: 'lesson-block' }, renderBlock(block, i, ctx))),
    endBox);

  const layout = h('div', { class: `activity ${lesson.workspace ? '' : 'single'}` }, content, lesson.workspace ? sideHost : null);
  main.replaceChildren(layout);
  refresh();
  if (lesson.workspace) {
    activeWorkspace = await mountWorkspace(sideHost, lesson.workspace, {
      onActivity: (log, handle) => watchers.forEach((fn) => fn(log, handle))
    });
  }
  return null;
}

// ---------------------------------------------------------------- Challenges

const filters = { section: 'all', level: 'all', status: 'all', q: '' };

function viewChallenges() {
  setTitle('Challenges');
  const solvedCount = allChallenges.filter((c) => store.solved(c.id)).length;
  const tbody = h('tbody');
  const summary = h('p', { class: 'muted small', 'aria-live': 'polite' });
  const render = () => {
    const q = filters.q.trim().toLowerCase();
    const rows = allChallenges.filter((c) =>
      (filters.section === 'all' || c.section.id === filters.section) &&
      (filters.level === 'all' || c.difficulty === filters.level) &&
      (filters.status === 'all' || (filters.status === 'solved') === !!store.solved(c.id)) &&
      (!q || `${c.title} ${c.goal} ${c.skills.join(' ')}`.toLowerCase().includes(q)));
    summary.textContent = `Showing ${rows.length} of ${allChallenges.length}.`;
    tbody.replaceChildren(...rows.map((c) => h('tr', {},
      h('td', {}, h('a', { href: `#/challenge/${c.id}` }, c.title), h('span', { class: 'sub' }, c.goal)),
      h('td', { class: 'hide-narrow' }, c.section.short),
      h('td', {}, level(c.difficulty)),
      h('td', { class: 'num' }, String(c.points)),
      h('td', { class: 'status' }, store.solved(c.id) ? h('span', { class: 'solved-mark' }, 'Solved') : h('span', { class: 'muted' }, store.opened(c.id) ? 'Started' : '')))));
    if (!rows.length) tbody.replaceChildren(h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'No challenges match those filters.')));
  };
  const select = (key, label, options) => h('label', {}, h('span', {}, label),
    h('select', { class: 'field', onchange: (e) => { filters[key] = e.target.value; render(); } },
      options.map(([value, text]) => h('option', { value, selected: filters[key] === value }, text))));
  const view = [
    h('header', { class: 'page-head' },
      h('h1', {}, 'Challenges'),
      h('p', { class: 'lede' }, `${allChallenges.length} capture-the-flag challenges across every topic. Each one hides a flag that looks like HW{...}. Find it and submit it.`),
      h('div', { class: 'facts' }, h('span', {}, h('strong', {}, `${solvedCount}/${allChallenges.length}`), ' solved'), h('span', {}, h('strong', {}, `${earnedPoints()}/${totalPoints}`), ' points'))),
    h('div', { class: 'filters' },
      h('label', { class: 'grow' }, h('span', {}, 'Search'), h('input', { class: 'field', type: 'search', value: filters.q, placeholder: 'Name or skill, like grep or SQL', oninput: (e) => { filters.q = e.target.value; render(); } })),
      select('section', 'Topic', [['all', 'All topics'], ...sections.map((s) => [s.id, s.short])]),
      select('level', 'Difficulty', [['all', 'Any'], ['easy', 'Easy'], ['medium', 'Medium'], ['hard', 'Hard']]),
      select('status', 'Status', [['all', 'Any'], ['unsolved', 'Not solved'], ['solved', 'Solved']])),
    summary,
    h('div', { class: 'table-scroll' }, h('table', { class: 'board' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Challenge'), h('th', { class: 'hide-narrow' }, 'Topic'), h('th', {}, 'Difficulty'), h('th', { class: 'num' }, 'Points'), h('th', { class: 'status' }, 'Status'))),
      tbody))
  ];
  render();
  return view;
}

async function viewChallenge(id) {
  const challenge = challenges.get(id);
  if (!challenge) return notFound();
  setTitle(challenge.title);
  store.open(id);
  const { section } = challenge;
  const flag = unseal(challenge.id, challenge.flag);
  const sideHost = h('div', { class: 'activity-side' });
  const hintsBox = h('section', { class: 'hints', 'aria-labelledby': 'hints-title' });
  const resultBox = h('div', { 'aria-live': 'polite' });
  const input = h('input', { class: 'field', type: 'text', placeholder: 'HW{...}', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Flag' });
  const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
  const form = h('form', { class: 'flag-form' }, h('label', { for: 'flag-input' }, 'Submit the flag'), h('div', { class: 'row', style: 'margin-top:.4rem' }, input, h('button', { class: 'btn primary', type: 'submit' }, 'Submit')), feedback);
  input.id = 'flag-input';
  const next = section.challenges[challenge.index + 1] ?? allChallenges.find((c) => !store.solved(c.id) && c.id !== id);
  let revealed = false;

  const writeup = () => h('section', { class: 'writeup' },
    h('h2', {}, 'Write-up'),
    h('h3', {}, 'How it works'), mdNode(challenge.writeup.how),
    h('h3', {}, 'Why it matters'), mdNode(challenge.writeup.why),
    challenge.writeup.fix ? [h('h3', {}, 'How to prevent it'), mdNode(challenge.writeup.fix)] : null);

  const renderResult = () => {
    const solved = store.solved(id);
    if (solved) {
      form.hidden = true;
      resultBox.replaceChildren(
        h('div', { class: 'solved-banner' }, h('strong', {}, 'Solved.'), h('span', {}, 'The flag was ', h('mark', { class: 'mono' }, flag), '.'), h('span', { class: 'muted' }, solved.hints ? `${solved.hints} ${solved.hints === 1 ? 'hint' : 'hints'} used.` : 'No hints used.')),
        writeup(),
        h('div', { class: 'next-up' }, next ? h('a', { class: 'btn primary', href: `#/challenge/${next.id}` }, `Next: ${next.title}`) : null, h('a', { class: 'btn', href: '#/challenges' }, 'All challenges')));
    } else if (revealed) {
      resultBox.replaceChildren(writeup());
    }
  };

  const renderHints = () => {
    const used = store.hintsUsed(id);
    const shown = challenge.hints.slice(0, used);
    const more = used < challenge.hints.length;
    hintsBox.replaceChildren(
      h('h2', { id: 'hints-title' }, 'Hints'),
      shown.length ? null : h('p', { class: 'muted small' }, `There are ${challenge.hints.length}. Each one gives away a bit more than the last, so try for a while first.`),
      shown.map((hint, i) => h('div', { class: 'hint' }, h('b', {}, `Hint ${i + 1}`), h('div', { html: md(hint) }))),
      h('div', { class: 'row' },
        more && !store.solved(id) ? h('button', { class: 'btn', type: 'button', onclick: () => { store.useHint(id); renderHints(); } }, `Show hint ${used + 1} of ${challenge.hints.length}`) : null,
        !more && !store.solved(id) && !revealed ? h('button', { class: 'btn quiet', type: 'button', onclick: () => { revealed = true; renderHints(); renderResult(); } }, 'Still stuck? Read the write-up') : null));
  };

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) return;
    if (!/^hw\{.+\}$/i.test(value)) {
      feedback.className = 'feedback no';
      feedback.textContent = 'Flags look like HW{...}, including the braces.';
      return;
    }
    if (normaliseFlag(value) === normaliseFlag(flag)) {
      store.solve(id);
      updateScore();
      announce(`Solved ${challenge.title}.`);
      renderHints();
      renderResult();
      return;
    }
    feedback.className = 'feedback no';
    feedback.textContent = 'That is not the flag for this challenge. Check for typos and extra spaces inside the braces.';
  });

  const prepare = (challenge.prepare ?? []).map((lid) => lessons.get(lid)).filter(Boolean);
  const content = h('div', { class: 'activity-main' },
    h('header', { class: 'activity-head' },
      h('p', { class: 'crumbs' }, h('a', { href: '#/challenges' }, 'Challenges'), ' / ', h('a', { href: `#/learn/${section.id}` }, section.title)),
      h('h1', {}, challenge.title),
      h('div', { class: 'facts' }, level(challenge.difficulty), h('span', {}, `${challenge.points} points`), store.solved(id) ? h('span', { class: 'solved-mark' }, 'Solved') : null)),
    mdNode(challenge.brief, 'div', 'prose brief'),
    h('div', { class: 'goal' }, h('h2', {}, 'Your goal'), h('p', { html: inline(challenge.goal) })),
    h('ul', { class: 'skills', 'aria-label': 'Skills' }, challenge.skills.map((s) => h('li', {}, s))),
    prepare.length ? h('p', { class: 'muted small', style: 'margin-top:1rem' }, 'Helpful lessons: ', ...prepare.flatMap((l, i) => [i ? ', ' : '', h('a', { href: `#/lesson/${l.id}` }, l.title)])) : null,
    form,
    resultBox,
    hintsBox);

  main.replaceChildren(h('div', { class: 'activity' }, content, sideHost));
  renderHints();
  renderResult();
  activeWorkspace = await mountWorkspace(sideHost, challenge.workspace, { flag });
  return null;
}

// ---------------------------------------------------------------- Review

function viewReview() {
  setTitle('Review');
  const cards = [];
  for (const lesson of lessons.values()) {
    for (const [term, definition] of lesson.terms ?? []) {
      const key = `${lesson.id}::${term}`;
      const state = store.card(key);
      if (state) cards.push({ key, term, definition, lesson, ...state });
    }
  }
  const due = cards.filter((c) => c.due <= Date.now()).sort((a, b) => a.box - b.box || a.due - b.due);
  const boxes = [1, 2, 3, 4, 5].map((b) => cards.filter((c) => Math.max(1, c.box) === b).length);
  const maxBox = Math.max(1, ...boxes);
  const head = h('header', { class: 'page-head' },
    h('h1', {}, 'Review'),
    h('p', { class: 'lede' }, 'Key terms from lessons you have finished come back here on a schedule: soon after you learn them, then less often each time you remember. A few minutes here is the cheapest way to make lessons stick.'));
  if (!cards.length) return [head, h('p', { class: 'empty' }, 'Nothing to review yet. Finish a lesson and its key terms will appear here.'), h('a', { class: 'btn primary', href: '#/learn' }, 'Go to lessons')];

  const chart = h('div', {},
    h('div', { class: 'boxes', 'aria-hidden': 'true' }, boxes.map((count) => h('span', { style: 'height:100%' }, h('b', { style: `height:${(count / maxBox) * 100}%` })))),
    h('p', { class: 'muted small' }, `${cards.length} cards. Boxes 1 to 5 from left to right: cards move right each time you remember them. ${boxes[4]} in the last box.`));
  const stage = h('div');
  let i = 0;
  const show = () => {
    const card = due[i];
    if (!card) {
      const upcoming = cards.filter((c) => c.due > Date.now()).sort((a, b) => a.due - b.due)[0];
      stage.replaceChildren(h('div', { class: 'empty' }, h('p', {}, 'You are done for now.'), upcoming ? h('p', {}, `Next card is due ${new Date(store.card(upcoming.key)?.due ?? upcoming.due).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}.`) : null));
      return;
    }
    const answer = h('div', { class: 'flashcard-def', hidden: true, html: md(card.definition) });
    const actions = h('div', { class: 'flashcard-actions' });
    const reveal = h('button', { class: 'btn primary', type: 'button' }, 'Show the answer');
    reveal.addEventListener('click', () => {
      answer.hidden = false;
      actions.replaceChildren(
        h('button', { class: 'btn primary', type: 'button', onclick: () => { store.reviewCard(card.key, true); i++; show(); } }, 'I knew it'),
        h('button', { class: 'btn', type: 'button', onclick: () => { store.reviewCard(card.key, false); i++; show(); } }, 'Not yet'));
      actions.querySelector('button').focus();
    });
    actions.replaceChildren(reveal);
    stage.replaceChildren(
      h('p', { class: 'muted small' }, `Card ${i + 1} of ${due.length} due now`),
      h('div', { class: 'flashcard' },
        h('div', { class: 'flashcard-face' },
          h('div', { class: 'flashcard-from' }, `From ${card.lesson.title}`),
          h('div', { class: 'flashcard-term' }, card.term),
          h('p', { class: 'muted', style: 'margin:0' }, 'Say what it means out loud, then check.'),
          answer),
        actions));
    reveal.focus();
  };
  show();
  return [head, chart, stage];
}

// ---------------------------------------------------------------- Tools

async function viewTools() {
  setTitle('Tools');
  const host = h('div');
  main.replaceChildren(
    h('header', { class: 'page-head' }, h('h1', {}, 'Analyst tools'), h('p', { class: 'lede' }, 'Small utilities for triage: decode what you find, pull indicators out of a message, convert timestamps, check whether an address sits inside a range. Use "Output to input" when data has been wrapped more than once.')),
    host);
  const { mountTools } = await import('./ui/tools.js');
  const body = h('div');
  host.append(h('section', { class: 'workspace' }, h('div', { class: 'workspace-bar' }, h('h2', {}, 'Toolbox')), body));
  mountTools(body, {});
  return null;
}

// ---------------------------------------------------------------- Resources

const RESOURCES = [
  { group: 'Practice, legally and for free', items: [
    ['picoCTF', 'https://picoctf.org', 'Beginner friendly capture-the-flag run by Carnegie Mellon. A huge archive of past challenges you can do any time.'],
    ['OverTheWire', 'https://overthewire.org/wargames/', 'Linux and security wargames you play over SSH. Bandit is the classic first level for learning the shell.'],
    ['TryHackMe', 'https://tryhackme.com', 'Guided rooms with short lessons and hands-on tasks. Strong blue-team and SOC paths. Free tier, with more behind a subscription.'],
    ['Hack The Box', 'https://www.hackthebox.com', 'Machines and challenges from beginner to hard, plus Academy modules. More open-ended once you have the basics.'],
    ['Blue Team Labs Online', 'https://blueteamlabs.online', 'Defensive investigations: log analysis, phishing, forensics and incident response scenarios.'],
    ['CyberDefenders', 'https://cyberdefenders.org', 'Blue-team challenges built from real evidence: packet captures, memory images and log sets to investigate.']
  ] },
  { group: 'Hands-on forensics and traffic', items: [
    ['Malware-Traffic-Analysis.net', 'https://www.malware-traffic-analysis.net', 'Real packet captures with exercises and answers. The best place to practise reading network traffic.'],
    ['Wireshark', 'https://www.wireshark.org', 'The standard packet analysis tool, free and open source. Its sample captures and documentation are excellent.'],
    ['CyberChef', 'https://gchq.github.io/CyberChef/', 'A browser-based tool for decoding, parsing and transforming data. The analyst tools here are a tiny version of it.']
  ] },
  { group: 'Reference you will use for real', items: [
    ['MITRE ATT&CK', 'https://attack.mitre.org', 'A catalogue of attacker techniques with IDs, used to describe and track what attackers do.'],
    ['OWASP Top 10', 'https://owasp.org/www-project-top-ten/', 'The most common and serious web application security risks, with guidance on each.'],
    ['NVD (National Vulnerability Database)', 'https://nvd.nist.gov', 'The record and CVSS score for every CVE. Where you look up a vulnerability.'],
    ['CISA Known Exploited Vulnerabilities', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'The list of vulnerabilities being exploited in the wild. The single best signal for what to patch first.'],
    ['SANS Internet Storm Center', 'https://isc.sans.edu', 'Daily, readable analysis of current threats and incidents from working analysts.']
  ] },
  { group: 'Learn the fundamentals', items: [
    ['Linux Journey', 'https://linuxjourney.com', 'A free, friendly path through the Linux basics, if you want more than this site\'s Linux topic.'],
    ['Julia Evans\' zines', 'https://wizardzines.com', 'Short, clear illustrated guides to networking, Linux tools, DNS and more.'],
    ['The Cyber Mentor on YouTube', 'https://www.youtube.com/@TCMSecurityAcademy', 'Practical, beginner-oriented security walkthroughs.']
  ] }
];

function viewResources() {
  setTitle('Resources');
  return [
    h('header', { class: 'page-head' },
      h('h1', {}, 'Where to go next'),
      h('p', { class: 'lede' }, 'HiddenWell teaches the foundations. When you are ready for more, these are established, legal places to keep learning and practising. Everything here is reputable and most of it is free. Only ever practise on systems these platforms give you, or ones you own.')),
    ...RESOURCES.map((section) => h('section', { style: 'margin-top:2rem' },
      h('h2', { class: 'subhead', style: 'margin-top:0' }, section.group),
      h('ul', { class: 'resource-list' }, section.items.map(([name, url, text]) => h('li', {},
        h('div', {}, h('a', { href: url, rel: 'noopener noreferrer', target: '_blank' }, name), h('span', { class: 'kind' }, new URL(url).hostname.replace(/^www\./, ''))),
        h('p', {}, text))))))
  ];
}

// ---------------------------------------------------------------- Progress

function viewProgress() {
  setTitle('Progress');
  const state = store.get();
  const lessonsDone = Object.keys(state.lessons).filter((id) => lessons.has(id)).length;
  const solved = allChallenges.filter((c) => store.solved(c.id));
  const hintsUsed = solved.reduce((sum, c) => sum + (store.solved(c.id).hints ?? 0), 0);
  const fileInput = h('input', { type: 'file', accept: 'application/json', hidden: true });
  const message = h('p', { class: 'muted small', 'aria-live': 'polite' });
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    try {
      store.import(await file.text());
      message.textContent = 'Progress imported.';
      updateScore();
      route();
    } catch (error) {
      message.textContent = error.message;
    }
  });
  const download = () => {
    const blob = new Blob([store.export()], { type: 'application/json' });
    const link = h('a', { href: URL.createObjectURL(blob), download: `hiddenwell-progress-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  };
  return [
    h('header', { class: 'page-head' }, h('h1', {}, 'Progress'), h('p', { class: 'lede' }, 'Everything here is stored in this browser only. Export it if you want to move to another computer.')),
    h('div', { class: 'stats' },
      h('div', {}, h('strong', {}, `${lessonsDone}/${lessons.size}`), h('span', {}, 'lessons finished')),
      h('div', {}, h('strong', {}, `${solved.length}/${allChallenges.length}`), h('span', {}, 'challenges solved')),
      h('div', {}, h('strong', {}, `${earnedPoints()}`), h('span', {}, `of ${totalPoints} points`)),
      h('div', {}, h('strong', {}, String(hintsUsed)), h('span', {}, 'hints used on solved challenges'))),
    h('h2', { class: 'subhead' }, 'By topic'),
    trackList(),
    h('div', { class: 'settings', style: 'margin-top:2.5rem' },
      h('section', {}, h('h2', {}, 'Move your progress'), h('p', { class: 'muted' }, 'Download a small file with your progress, then import it on another browser.'),
        h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: download }, 'Export progress'), h('button', { class: 'btn', type: 'button', onclick: () => fileInput.click() }, 'Import progress'), fileInput), message),
      h('section', {}, h('h2', {}, 'Start over'), h('p', { class: 'muted' }, 'Clears lessons, solved challenges, hints and review cards from this browser. This cannot be undone.'),
        h('button', { class: 'btn', type: 'button', onclick: () => {
          if (confirm('Clear all HiddenWell progress in this browser?')) {
            store.reset();
            updateScore();
            route();
          }
        } }, 'Clear all progress')))
  ];
}

// ---------------------------------------------------------------- About

function viewAbout() {
  setTitle('How it works');
  return [
    h('header', { class: 'page-head' }, h('h1', {}, 'How HiddenWell works')),
    mdNode(`
HiddenWell is a free place to learn the basics of defensive cybersecurity by practising them. Each topic is a short run of lessons followed by capture-the-flag challenges, where the goal is to investigate some evidence and find a hidden string that looks like \`HW{...}\`. The focus is blue-team work: analysing logs, email, files and network traffic to work out what happened, rather than attacking systems.

**Everything runs in your browser.** The terminal is a Linux-style shell written in JavaScript, with its own pretend filesystem. The SIEM, the mailbox, the packet viewer and the analyst tools are all small programs on this page, working on evidence that is generated here too. None of it can reach the internet or your real files, so there is nothing you can break by experimenting.

**Your progress stays with you.** It is saved in this browser's local storage. There are no accounts, cookies for tracking, or analytics. You can export and import your progress from the Progress page.

**About the flags.** Because the whole site runs on your computer, a determined person could dig the answers out of the code. The flags are stored scrambled so they do not show up by accident or in a quick search, but that is all. Solving the challenge is the point; reading the source to find a flag only cheats you.

**Only practise on systems you own or have permission to test.** The skills here are real and defensive, but the line matters everywhere. Using security techniques against other people's systems without permission is illegal in most countries and causes real harm. The [Resources](#/resources) page lists established, legal places to keep learning and practising.

**Open source.** HiddenWell is MIT licensed. Fonts are Atkinson Hyperlegible by the Braille Institute and JetBrains Mono, both under the SIL Open Font License.
`, 'div', 'prose')
  ];
}

function notFound() {
  setTitle('Not found');
  return [h('header', { class: 'page-head' }, h('h1', {}, 'There is nothing at this address'), h('p', { class: 'lede' }, 'The link may be old. Lessons and challenges are listed on the Learn and Challenges pages.')), h('a', { class: 'btn primary', href: '#/learn' }, 'Go to Learn')];
}

// ---------------------------------------------------------------- Router

const ROUTES = [
  [/^$/, viewHome, 'home'],
  [/^learn$/, viewLearn, 'learn'],
  [/^learn\/([\w-]+)$/, viewSection, 'learn'],
  [/^lesson\/([\w-]+)$/, viewLesson, 'learn'],
  [/^challenges$/, viewChallenges, 'challenges'],
  [/^challenge\/([\w-]+)$/, viewChallenge, 'challenges'],
  [/^review$/, viewReview, 'review'],
  [/^tools$/, viewTools, 'tools'],
  [/^resources$/, viewResources, 'resources'],
  [/^progress$/, viewProgress, 'progress'],
  [/^about$/, viewAbout, null]
];

let lastPath = null;
async function route() {
  const path = location.hash.replace(/^#\/?/, '').replace(/\/$/, '');
  const match = ROUTES.map(([re, view, nav]) => ({ m: re.exec(path), view, nav })).find((r) => r.m);
  activeWorkspace = null;
  document.querySelectorAll('.nav a').forEach((a) => {
    a.toggleAttribute('aria-current', !!match?.nav && a.getAttribute('href') === `#/${match.nav}`);
    if (a.hasAttribute('aria-current')) a.setAttribute('aria-current', 'page');
  });
  document.getElementById('nav').classList.remove('open');
  document.querySelector('.menu-button').setAttribute('aria-expanded', 'false');
  const result = match ? await match.view(...match.m.slice(1)) : notFound();
  if (result) main.replaceChildren(...[result].flat());
  if (path !== lastPath) {
    window.scrollTo(0, 0);
    if (lastPath !== null) main.focus({ preventScroll: true });
  }
  lastPath = path;
}

document.getElementById('theme-toggle').addEventListener('click', () => {
  const root = document.documentElement;
  const current = root.dataset.theme ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  writePref('theme', next);
  announce(`${next === 'dark' ? 'Dark' : 'Light'} theme`);
});

document.querySelector('.menu-button').addEventListener('click', (event) => {
  const nav = document.getElementById('nav');
  const open = nav.classList.toggle('open');
  event.currentTarget.setAttribute('aria-expanded', String(open));
});

window.addEventListener('hashchange', route);
updateScore();
route();

export { escapeHtml };
