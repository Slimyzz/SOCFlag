// Progress lives in this browser's localStorage and nowhere else. Every read
// and write is guarded because storage can be blocked (private windows,
// strict settings); the site still works, it just forgets on reload.

const KEY = 'hiddenwell:progress:v1';
const EMPTY = () => ({ lessons: {}, answers: {}, solved: {}, hints: {}, cards: {}, opened: {}, last: null });

let state = load();
const listeners = new Set();

function load() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...EMPTY(), ...JSON.parse(raw) } : EMPTY();
  } catch {
    return EMPTY();
  }
}

function save() {
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {}
  for (const fn of listeners) fn(state);
}

export const store = {
  get: () => state,
  subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },

  answered: (blockId) => !!state.answers[blockId],
  answer(blockId) {
    if (state.answers[blockId]) return;
    state.answers[blockId] = Date.now();
    save();
  },

  lessonDone: (id) => !!state.lessons[id],
  completeLesson(id) {
    if (state.lessons[id]) return;
    state.lessons[id] = Date.now();
    save();
  },

  solved: (id) => state.solved[id] ?? null,
  solve(id) {
    if (state.solved[id]) return;
    state.solved[id] = { at: Date.now(), hints: state.hints[id] ?? 0 };
    save();
  },

  hintsUsed: (id) => state.hints[id] ?? 0,
  useHint(id) {
    state.hints[id] = (state.hints[id] ?? 0) + 1;
    save();
  },

  opened: (id) => !!state.opened[id],
  open(id) {
    state.opened[id] = Date.now();
    state.last = id;
    save();
  },

  // Flashcards use a Leitner schedule: a correct recall moves a card up a
  // box and pushes its next review further out; a miss sends it to box 1.
  card: (key) => state.cards[key] ?? null,
  reviewCard(key, remembered) {
    const intervals = [0, 1, 3, 7, 16, 35];
    const current = state.cards[key]?.box ?? 0;
    const box = remembered ? Math.min(current + 1, intervals.length - 1) : 1;
    state.cards[key] = { box, due: Date.now() + intervals[box] * 86400000 };
    save();
  },
  seedCard(key) {
    if (state.cards[key]) return;
    state.cards[key] = { box: 0, due: Date.now() };
    save();
  },

  export: () => JSON.stringify({ app: 'hiddenwell', version: 1, exported: new Date().toISOString(), progress: state }, null, 2),
  import(json) {
    const data = JSON.parse(json);
    if (data?.app !== 'hiddenwell' || !data.progress) throw new Error('That file is not a HiddenWell progress export.');
    state = { ...EMPTY(), ...data.progress };
    save();
  },
  reset() {
    state = EMPTY();
    save();
  }
};

export function readPref(key, fallback) {
  try {
    return localStorage.getItem(`hiddenwell:${key}`) ?? fallback;
  } catch {
    return fallback;
  }
}

export function writePref(key, value) {
  try {
    localStorage.setItem(`hiddenwell:${key}`, value);
  } catch {}
}
