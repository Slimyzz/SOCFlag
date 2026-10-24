// An in-memory Unix-style filesystem with owners, groups and permission bits.
// It is small on purpose: enough for the lessons to teach real habits
// (hidden files, permissions, absolute and relative paths) without a VM.
import { utf8 } from '../lib/bytes.js';

export class FsError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

const ENOENT = () => new FsError('No such file or directory', 'ENOENT');
const EACCES = () => new FsError('Permission denied', 'EACCES');
const ENOTDIR = () => new FsError('Not a directory', 'ENOTDIR');
const EISDIR = () => new FsError('Is a directory', 'EISDIR');
const EEXIST = () => new FsError('File exists', 'EEXIST');

export const DEFAULT_USERS = {
  root: { name: 'root', uid: 0, groups: ['root'], home: '/root' },
  learner: { name: 'learner', uid: 1000, groups: ['learner'], home: '/home/learner' }
};

function makeNode(type, name, props = {}) {
  return {
    type,
    name,
    owner: props.owner ?? 'root',
    group: props.group ?? props.owner ?? 'root',
    mode: props.mode ?? (type === 'dir' ? 0o755 : 0o644),
    mtime: props.mtime ?? 0,
    data: type === 'file' ? props.data ?? new Uint8Array() : undefined,
    children: type === 'dir' ? new Map() : undefined,
    parent: null
  };
}

export function normalise(path, cwd = '/') {
  const parts = (path.startsWith('/') ? path : `${cwd}/${path}`).split('/');
  const stack = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  return '/' + stack.join('/');
}

export function basename(path) {
  const clean = path.replace(/\/+$/, '');
  return clean.slice(clean.lastIndexOf('/') + 1) || '/';
}

export function dirname(path) {
  const clean = path.replace(/\/+$/, '');
  const index = clean.lastIndexOf('/');
  return index <= 0 ? '/' : clean.slice(0, index);
}

export class FileSystem {
  constructor({ users = DEFAULT_USERS, now = Date.UTC(2026, 2, 14, 10, 0) } = {}) {
    this.users = users;
    this.now = now;
    this.root = makeNode('dir', '', { mtime: now });
    this.root.parent = this.root;
  }

  user(name) {
    return this.users[name] ?? { name, uid: 65534, groups: [name], home: '/' };
  }

  // Permission check for one of r (4), w (2), x (1).
  allowed(node, userName, bit) {
    const user = this.user(userName);
    if (user.uid === 0) return bit !== 1 || node.type === 'dir' || (node.mode & 0o111) !== 0;
    if (node.owner === user.name) return (node.mode >> 6 & bit) !== 0;
    if (user.groups.includes(node.group)) return (node.mode >> 3 & bit) !== 0;
    return (node.mode & bit) !== 0;
  }

  // Walks to a node. Directories along the way need execute permission,
  // exactly like a real kernel, which is what makes the permission lessons work.
  lookup(path, userName = 'root') {
    const abs = normalise(path);
    let node = this.root;
    if (abs === '/') return node;
    for (const part of abs.slice(1).split('/')) {
      if (node.type !== 'dir') throw ENOTDIR();
      if (!this.allowed(node, userName, 1)) throw EACCES();
      const next = node.children.get(part);
      if (!next) throw ENOENT();
      node = next;
    }
    return node;
  }

  exists(path) {
    try {
      this.lookup(path);
      return true;
    } catch {
      return false;
    }
  }

  pathOf(node) {
    const parts = [];
    while (node !== this.root) {
      parts.unshift(node.name);
      node = node.parent;
    }
    return '/' + parts.join('/');
  }

  readFile(path, userName) {
    const node = this.lookup(path, userName);
    if (node.type === 'dir') throw EISDIR();
    if (!this.allowed(node, userName, 4)) throw EACCES();
    return node.data;
  }

  list(path, userName) {
    const node = this.lookup(path, userName);
    if (node.type !== 'dir') return [node];
    if (!this.allowed(node, userName, 4)) throw EACCES();
    return [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name, 'en'));
  }

  // Creates any missing parent directories as root. Used by the fixture loader.
  ensureDir(path, props = {}) {
    let node = this.root;
    for (const part of normalise(path).slice(1).split('/').filter(Boolean)) {
      let next = node.children.get(part);
      if (!next) {
        next = makeNode('dir', part, { mtime: this.now, ...props });
        next.parent = node;
        node.children.set(part, next);
      }
      node = next;
    }
    return node;
  }

  writeFile(path, data, userName, { append = false, props } = {}) {
    const abs = normalise(path);
    const bytes = typeof data === 'string' ? utf8(data) : data;
    let existing = null;
    try {
      existing = this.lookup(abs, userName ?? 'root');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (existing) {
      if (existing.type === 'dir') throw EISDIR();
      if (userName && !this.allowed(existing, userName, 2)) throw EACCES();
      existing.data = append ? concatBytes(existing.data, bytes) : bytes;
      existing.mtime = this.now;
      if (props) Object.assign(existing, props);
      return existing;
    }
    const parent = this.lookup(dirname(abs), userName ?? 'root');
    if (parent.type !== 'dir') throw ENOTDIR();
    if (userName && !this.allowed(parent, userName, 2)) throw EACCES();
    const owner = userName ?? 'root';
    const node = makeNode('file', basename(abs), { owner, group: this.user(owner).groups[0], mtime: this.now, data: bytes, ...props });
    node.parent = parent;
    parent.children.set(node.name, node);
    return node;
  }

  mkdir(path, userName, { parents = false } = {}) {
    const abs = normalise(path);
    if (this.exists(abs)) {
      if (parents && this.lookup(abs).type === 'dir') return this.lookup(abs);
      throw EEXIST();
    }
    if (parents && !this.exists(dirname(abs))) this.mkdir(dirname(abs), userName, { parents });
    const parent = this.lookup(dirname(abs), userName);
    if (parent.type !== 'dir') throw ENOTDIR();
    if (!this.allowed(parent, userName, 2)) throw EACCES();
    const node = makeNode('dir', basename(abs), { owner: userName, group: this.user(userName).groups[0], mode: 0o755, mtime: this.now });
    node.parent = parent;
    parent.children.set(node.name, node);
    return node;
  }

  remove(path, userName, { recursive = false } = {}) {
    const node = this.lookup(path, userName);
    if (node === this.root) throw EACCES();
    if (node.type === 'dir' && !recursive) throw EISDIR();
    if (!this.allowed(node.parent, userName, 2)) throw EACCES();
    node.parent.children.delete(node.name);
  }

  move(from, to, userName) {
    const node = this.lookup(from, userName);
    let target = normalise(to);
    if (this.exists(target) && this.lookup(target, userName).type === 'dir') target = normalise(`${target}/${node.name}`);
    const parent = this.lookup(dirname(target), userName);
    if (!this.allowed(node.parent, userName, 2) || !this.allowed(parent, userName, 2)) throw EACCES();
    node.parent.children.delete(node.name);
    node.name = basename(target);
    node.parent = parent;
    parent.children.set(node.name, node);
  }

  // Depth-first walk used by find and grep -r. Unreadable directories are
  // reported through onError instead of stopping the walk.
  *walk(path, userName, onError = () => {}, depth = 0) {
    let node;
    try {
      node = this.lookup(path, userName);
    } catch (error) {
      onError(path, error);
      return;
    }
    yield { path, node, depth };
    if (node.type !== 'dir') return;
    if (!this.allowed(node, userName, 4) || !this.allowed(node, userName, 1)) {
      onError(path, EACCES());
      return;
    }
    for (const child of [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      yield* this.walk(path === '/' ? `/${child.name}` : `${path}/${child.name}`, userName, onError, depth + 1);
    }
  }
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// Builds a filesystem from a plain object of paths. A trailing slash makes a
// directory. Values can be strings, bytes, or { content, mode, owner, group, mtime }.
export function buildFileSystem(spec = {}, { users, now, commands = [] } = {}) {
  const fs = new FileSystem({ users, now });
  const day = 86400000;
  const base = {
    '/bin/': {}, '/usr/bin/': {}, '/etc/': {}, '/tmp/': { mode: 0o1777 }, '/var/log/': {}, '/root/': { mode: 0o700 },
    '/home/': {}, '/dev/': {},
    '/etc/hostname': 'socflag\n',
    '/etc/os-release': 'NAME="SOCFlag Linux"\nVERSION="3.0 (practice)"\nID=socflag\n'
  };
  const userList = Object.values(fs.users);
  base['/etc/passwd'] = userList.map((u) => `${u.name}:x:${u.uid}:${u.uid}:${u.gecos ?? ''}:${u.home}:${u.shell ?? '/bin/bash'}`).join('\n') + '\n';
  base['/etc/group'] = [...new Set(userList.flatMap((u) => u.groups))].map((g, i) => `${g}:x:${fs.users[g]?.uid ?? 2000 + i}:${userList.filter((u) => u.groups.includes(g) && u.name !== g).map((u) => u.name).join(',')}`).join('\n') + '\n';
  for (const user of userList) {
    if (user.uid >= 1000) base[`${user.home}/`] = { owner: user.name, group: user.groups[0], mode: 0o755 };
  }
  for (const name of commands) {
    base[`/usr/bin/${name}`] = { content: Uint8Array.of(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...utf8(`socflag builtin: ${name}`)), mode: 0o755, mtime: fs.now - 400 * day };
  }

  const entries = Object.entries({ ...base, ...spec }).sort(([a], [b]) => a.split('/').length - b.split('/').length || a.localeCompare(b));
  for (const [rawPath, value] of entries) {
    const props = value && typeof value === 'object' && !(value instanceof Uint8Array) ? value : { content: value };
    const meta = {};
    for (const key of ['owner', 'group', 'mode']) if (props[key] !== undefined) meta[key] = props[key];
    if (props.mtime !== undefined) meta.mtime = typeof props.mtime === 'number' && props.mtime < 10000 ? fs.now - props.mtime * day : props.mtime;
    if (!meta.owner) {
      const home = userList.find((u) => u.uid >= 1000 && rawPath.startsWith(u.home + '/') && rawPath !== `${u.home}/`);
      if (home) meta.owner = home.name;
    }
    if (meta.owner && !meta.group) meta.group = fs.user(meta.owner).groups[0];
    if (rawPath.endsWith('/')) {
      const dir = fs.ensureDir(rawPath);
      Object.assign(dir, meta);
    } else {
      const parent = fs.ensureDir(dirname(rawPath));
      if (meta.owner && parent.owner === 'root' && parent !== fs.root && fs.pathOf(parent).startsWith(fs.user(meta.owner).home + '/')) {
        parent.owner = meta.owner;
        parent.group = meta.group;
      }
      const content = props.content ?? '';
      fs.writeFile(rawPath, content, null, { props: { mtime: fs.now - 3 * day, ...meta } });
    }
  }
  return fs;
}
