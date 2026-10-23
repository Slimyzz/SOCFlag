// Mounts the hands-on part of a lesson or challenge next to the text.
// Every workspace runs inside this page: no server, no network.
import { h } from '../core/dom.js';
import { createMachine } from '../shell/index.js';
import { mountTerminal } from './terminal.js';

const TITLES = { shell: 'Terminal', siem: 'SIEM search', mail: 'Mailbox', packets: 'Packet capture', tools: 'Evidence and tools', case: 'Case workspace' };
export const TRY_LABELS = { shell: 'Type it', siem: 'Run it', packets: 'Apply it' };

export function resolveSpec(spec, flag) {
  return typeof spec === 'function' ? spec(flag) : spec;
}

// Mounts one workspace of a given type into body and returns its handle.
async function mountSpec(body, spec, report, extra) {
  switch (spec.type) {
    case 'shell': {
      const machine = createMachine(spec, report);
      const terminal = mountTerminal(body, machine, { motd: spec.motd });
      return { machine, terminal, fs: machine.fs, shell: machine.shell };
    }
    case 'siem': {
      const { mountSiem } = await import('./siem.js');
      return mountSiem(body, spec, report);
    }
    case 'mail': {
      const { mountMail } = await import('./mail.js');
      return mountMail(body, spec, report);
    }
    case 'packets': {
      const { mountPackets } = await import('./packets.js');
      return mountPackets(body, spec, report);
    }
    case 'tools': {
      const { mountTools } = await import('./tools.js');
      return mountTools(body, spec, report);
    }
    case 'case':
      return mountCase(body, spec, report, extra);
    default:
      body.replaceChildren(h('p', { class: 'empty' }, `Unknown workspace type ${spec.type}`));
      return {};
  }
}

// A case puts several workspaces behind tabs, so one investigation can move
// between the mailbox, the SIEM, a host and a packet capture. Each tab keeps
// its state while you look at the others.
async function mountCase(body, spec, report, extra) {
  const panes = spec.tabs.map(() => h('div', { class: 'case-pane', role: 'tabpanel', hidden: true }));
  const handles = [];
  const caseHandle = {
    tabs: handles,
    current: 0,
    get terminal() { return handles[caseHandle.current]?.terminal; },
    show
  };
  const buttons = spec.tabs.map((tab, i) => h('button', { type: 'button', role: 'tab', 'aria-selected': 'false', onclick: () => show(i) }, tab.title ?? TITLES[tab.type]));
  async function show(i) {
    caseHandle.current = i;
    buttons.forEach((b, j) => b.setAttribute('aria-selected', String(i === j)));
    panes.forEach((pane, j) => { pane.hidden = i !== j; });
    if (!handles[i]) handles[i] = await mountSpec(panes[i], spec.tabs[i], (event) => report({ ...event, tab: i }), extra);
    report({ type: 'case-tab', tab: i });
  }
  extra.replaceChildren();
  body.replaceChildren(h('div', { class: 'case' }, h('div', { class: 'case-tabs', role: 'tablist', 'aria-label': 'Evidence sources' }, buttons), panes));
  await show(0);
  return caseHandle;
}

export async function mountWorkspace(host, rawSpec, { flag = '', onActivity } = {}) {
  const spec = resolveSpec(rawSpec, flag);
  const body = h('div', { class: 'workspace-body' });
  const resetButton = h('button', { class: 'btn small', type: 'button', title: 'Put everything back the way it started' }, 'Reset');
  const extra = h('span', { class: 'row' });
  const frame = h('section', { class: 'workspace', 'aria-label': spec.title ?? TITLES[spec.type] },
    h('div', { class: 'workspace-bar' }, h('h2', {}, spec.title ?? TITLES[spec.type]), h('span', { class: 'row' }, extra, resetButton)),
    body,
    spec.note !== false ? h('p', { class: 'workspace-note' }, spec.note ?? 'Runs in this page only. Nothing you do here leaves your browser.') : null);
  host.replaceChildren(frame);

  const log = [];
  let handle = {};
  const report = (event) => {
    log.push(event);
    onActivity?.(log, handle);
  };

  const start = async () => {
    log.length = 0;
    extra.replaceChildren();
    handle = await mountSpec(body, spec, report, extra);
    onActivity?.(log, handle);
  };

  resetButton.addEventListener('click', async () => {
    await start();
    handle.terminal?.focus();
  });
  await start();

  return {
    get handle() { return handle; },
    get log() { return log; },
    terminal: () => handle.terminal,
    // Sends a command from a worked example into whichever tool is open.
    tryIt(command) {
      const target = handle.tabs ? handle.tabs[handle.current] ?? {} : handle;
      if (target.terminal) target.terminal.type(command);
      else if (target.run) target.run(command);
      else if (target.apply) target.apply(command);
    }
  };
}
