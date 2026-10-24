// Builds a ready-to-use practice machine from a workspace description.
import { buildFileSystem, DEFAULT_USERS } from './vfs.js';
import { Shell } from './shell.js';
import { createCommands, COMMAND_NAMES } from './commands.js';

export function createMachine(config = {}, onEvent) {
  const users = { ...DEFAULT_USERS };
  for (const user of config.users ?? []) {
    users[user.name] = { home: `/home/${user.name}`, groups: [user.name], ...user };
  }
  if (config.learnerGroups) users.learner = { ...users.learner, groups: ['learner', ...config.learnerGroups] };
  const fs = buildFileSystem(config.files ?? {}, { users, now: config.now, commands: COMMAND_NAMES });
  const shell = new Shell({
    fs,
    commands: createCommands(),
    user: config.user ?? 'learner',
    cwd: config.cwd,
    env: config.env,
    hostname: config.hostname ?? 'socflag',
    sudoRules: config.sudo ?? [],
    onEvent
  });
  shell.processes = config.processes ?? [];
  return { fs, shell };
}
