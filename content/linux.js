import { ran, random, clf } from './helpers.js';
import { utf8, toBase64, toHex, concat } from '../assets/js/lib/bytes.js';

// One practice machine shared by the Linux lessons, so what you learn in
// one lesson is still there in the next.
function accessLog(lines = 240, seed = 7) {
  const r = random(seed);
  const ips = ['10.0.4.21', '10.0.4.22', '172.16.9.3', '192.168.1.50', '203.0.113.9', '198.51.100.23'];
  const paths = ['/', '/index.html', '/about', '/login', '/static/app.css', '/static/app.js', '/api/items', '/contact'];
  const out = [];
  for (let i = 0; i < lines; i++) {
    const path = r.pick(paths);
    const status = path === '/login' && r.next() < 0.3 ? 401 : r.next() < 0.04 ? 404 : 200;
    out.push(`${r.pick(ips)} - - [${clf(i * 37)}] "${path === '/login' ? 'POST' : 'GET'} ${path} HTTP/1.1" ${status} ${r.int(180, 5400)}`);
  }
  return out.join('\n') + '\n';
}

export function binaryWith(strings, seed, size = 1400) {
  const r = random(seed);
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = r.next() < 0.5 ? r.int(0, 31) : r.int(128, 255);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  let at = 120;
  for (const s of strings) {
    const encoded = utf8(s);
    bytes.set(encoded, at);
    bytes[at + encoded.length] = 0;
    at += encoded.length + r.int(40, 160);
  }
  return bytes;
}

export function practiceFiles() {
  return {
    '/home/learner/notes/todo.txt': 'Things to do this week\n- rotate the web server logs\n- ask Priya about the backup job\n- find out why /srv/shared is locked\n',
    '/home/learner/notes/meeting.txt': 'Weekly sync, 12 March\n\nPriya: backups are running nightly now.\nTom: the login page had a lot of failed attempts on Tuesday.\nAction: Tom to check logs/access.log and report the noisiest IP.\n',
    '/home/learner/.profile': '# Runs when you log in.\nexport EDITOR=nano\n',
    '/home/learner/.plan': 'If you are reading this, you found a hidden file. ls -a shows names that start with a dot.\n',
    '/home/learner/logs/access.log': accessLog(),
    '/home/learner/logs/auth.log': [
      'Mar 13 06:01:12 web sshd[811]: Accepted publickey for priya from 10.0.4.21 port 51022',
      'Mar 13 06:14:40 web sshd[902]: Failed password for root from 203.0.113.9 port 40112',
      'Mar 13 06:14:43 web sshd[902]: Failed password for root from 203.0.113.9 port 40114',
      'Mar 13 06:14:47 web sshd[902]: Failed password for admin from 203.0.113.9 port 40118',
      'Mar 13 07:30:05 web sshd[1201]: Accepted password for tom from 10.0.4.22 port 50210'
    ].join('\n') + '\n',
    '/home/learner/projects/site/index.html': '<!doctype html>\n<title>Example Co</title>\n<h1>Welcome</h1>\n<!-- TODO remove test account before launch -->\n',
    '/home/learner/projects/site/robots.txt': 'User-agent: *\nDisallow: /staging/\n',
    '/home/learner/evidence/report.txt': { content: concat(Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13), utf8('IHDR'), new Uint8Array(40)) },
    '/home/learner/evidence/firmware.bin': binaryWith(['GCC: (Debian 12.2.0) 12.2.0', 'wifi_ssid=office-guest', 'admin_user=root', 'update_url=http://updates.example.internal/fw', 'Copyright 2024 Example Devices'], 11),
    '/home/learner/evidence/message.b64': `${toBase64(utf8('Base64 is an encoding, not encryption. Anyone can reverse it.\n'))}\n`,
    '/srv/shared/': { owner: 'root', group: 'staff', mode: 0o750 },
    '/srv/shared/rota.txt': { content: 'On call: Priya (Mon to Wed), Tom (Thu to Sun)\n', owner: 'root', group: 'staff', mode: 0o640 },
    '/home/learner/private.txt': { content: 'Only I should be able to read this.\n', mode: 0o644 },
    '/var/log/syslog': 'Mar 13 06:00:01 web CRON[700]: (root) CMD (/usr/local/bin/backup.sh)\nMar 13 06:00:04 web backup.sh: backup finished, 412 files\n'
  };
}

function lessonMachine(motd) {
  return { type: 'shell', motd, files: practiceFiles(), users: [{ name: 'priya', uid: 1001 }, { name: 'tom', uid: 1002 }] };
}

export default {
  id: 'linux',
  title: 'Linux fundamentals',
  short: 'Linux',
  summary: 'Move around a Linux system, read and search files, understand permissions, and chain small tools into useful one-liners.',
  intro: 'Most servers run Linux, and most security work starts at a terminal. This topic takes you from your first command to building pipelines that pull one line of evidence out of thousands.',
  outcomes: [
    'Navigate with absolute and relative paths',
    'Read files, including hidden ones',
    'Explain and change Linux permissions',
    'Find files with find and text with grep',
    'Chain commands with pipes and redirection',
    'Inspect unknown files with file, strings and xxd'
  ],
  lessons: [
    {
      id: 'linux-shell',
      title: 'Your first commands',
      summary: 'What a shell is, how to read the prompt, and the shape of every command.',
      minutes: 8,
      terms: [
        ['shell', 'A program that reads the commands you type, runs them, and shows you the output. Bash is the most common one on Linux.'],
        ['prompt', 'The text the shell prints when it is ready for a command. Here it shows your user name, the machine name and the folder you are in.'],
        ['argument', 'A value you pass to a command, like a file name. In `cat notes.txt`, the argument is `notes.txt`.'],
        ['option', 'A switch that changes how a command behaves. Options usually start with a dash, like `-l` or `--all`.']
      ],
      workspace: lessonMachine('Practice machine. Type commands below and press Enter. Try: whoami\n'),
      blocks: [
        { type: 'text', body: 'A **shell** is a program that waits for you to type a command, runs it, and prints the result. When people say "open a terminal" they mean open a window running a shell.\n\nThe terminal on the right is a real shell running in this page. It has its own files and nothing you do there can touch your computer, so try things freely.' },
        { type: 'example', title: 'Reading the prompt', steps: [
          { out: 'learner@hiddenwell:~$', note: '`learner` is who you are logged in as, `hiddenwell` is the machine, `~` is your home folder, and `$` means you are a normal user. Root (the administrator) gets `#` instead.' },
          { cmd: 'whoami', out: 'learner', note: 'Prints your user name. Useful when you are not sure which account a shell belongs to.' },
          { cmd: 'pwd', out: '/home/learner', note: 'Print working directory: the folder you are in right now.' },
          { cmd: 'ls', out: 'evidence  logs  notes  private.txt  projects', note: 'Lists what is in the current folder.' }
        ] },
        { type: 'text', body: 'Every command has the same shape: the **command name**, then optional **options** that change its behaviour, then **arguments** that say what to work on.' },
        { type: 'table', head: ['Part', 'In `ls -l notes`', 'What it does'], rows: [['Command', '`ls`', 'The program to run'], ['Option', '`-l`', 'Long format: one file per line with details'], ['Argument', '`notes`', 'Which folder to list']] },
        { type: 'task', text: 'In the terminal, run `whoami`, then `pwd`, then `ls`.', hint: 'Type each one and press Enter. The "Type it" buttons above fill them in for you.', check: (log) => ran(log, 'whoami') && ran(log, 'pwd') && ran(log, 'ls') },
        { type: 'predict', question: 'You are at `/home/learner` and run `ls notes`. What do you see?', options: [
          { text: 'The files inside the notes folder', correct: true, why: 'The argument tells ls which folder to list, so it shows what is inside `notes` without moving you there.' },
          { text: 'An error, because you have to cd into notes first', why: 'Most commands accept a path as an argument. You only need cd if you want to stay there.' },
          { text: 'The word notes', why: 'That is what `echo notes` would do. ls lists the contents of a folder.' }
        ] },
        { type: 'task', text: 'List the contents of the `notes` folder without changing directory.', check: (log) => ran(log, 'ls', (a) => /notes/.test(a)) },
        { type: 'note', title: 'Getting help', body: 'Type `help` to see every command this practice shell knows, and `man ls` (or `man` plus any command) for its options. On a real Linux system, `man` opens the full manual.' },
        { type: 'quiz', question: 'What does the `$` at the end of the prompt tell you?', options: [
          { text: 'You are a normal user, not root', correct: true, why: 'Bash ends the prompt with `#` for root and `$` for everyone else. It is a quick way to notice you have more power than usual.' },
          { text: 'The last command cost money', why: 'It is just a marker that the shell is ready, with a hint about which user you are.' },
          { text: 'You are inside a variable', why: 'Variables do start with `$` when you use them, like `$HOME`, but at the end of the prompt it means something else.' }
        ] }
      ]
    },
    {
      id: 'linux-paths',
      title: 'Moving around',
      summary: 'The single file tree, absolute and relative paths, and the shortcuts . .. and ~.',
      minutes: 10,
      terms: [
        ['root directory', 'The top of the Linux file tree, written `/`. Every file on the system lives somewhere below it.'],
        ['absolute path', 'A path that starts with `/` and spells out the full route from the root, like `/var/log/syslog`. It means the same thing wherever you are.'],
        ['relative path', 'A path that starts from your current folder, like `logs/access.log`. It depends on where you are.'],
        ['home directory', 'Your own folder, usually `/home/yourname`. The shortcut `~` stands for it.']
      ],
      workspace: lessonMachine('Practice machine. Use cd to move and pwd to check where you are.\n'),
      blocks: [
        { type: 'text', body: 'Windows has a separate tree for each drive (C:, D:). Linux has exactly one tree, starting at `/`, which is called the **root directory**. Disks, USB sticks and even some hardware all appear as folders somewhere in that tree.' },
        { type: 'table', head: ['Folder', 'What usually lives there'], rows: [['`/home`', 'One folder per user'], ['`/root`', 'Home of the root user, normally locked'], ['`/etc`', 'System configuration files'], ['`/var/log`', 'Log files'], ['`/tmp`', 'Temporary files anyone can write'], ['`/usr/bin`', 'Programs, including the commands you run']] },
        { type: 'text', body: 'You can point at a file in two ways. An **absolute path** starts with `/` and gives the full route: `/home/learner/logs/auth.log`. A **relative path** starts from wherever you are now: if you are in `/home/learner`, then `logs/auth.log` points at the same file.' },
        { type: 'example', title: 'Three shortcuts', steps: [
          { cmd: 'cd logs', note: 'Move into the logs folder, using a relative path.' },
          { cmd: 'pwd', out: '/home/learner/logs' },
          { cmd: 'cd ..', note: '`..` means the folder above this one. `.` means this folder.' },
          { cmd: 'cd /var/log', note: 'An absolute path works from anywhere.' },
          { cmd: 'cd ~', note: '`~` is your home folder. Plain `cd` with nothing after it goes home too.' },
          { cmd: 'pwd', out: '/home/learner' }
        ] },
        { type: 'task', text: 'Go to `/var/log` and list what is there. Then come back home.', hint: '`cd /var/log`, then `ls`, then `cd`.', check: (log) => {
          const listed = log.findIndex((e) => e.name === 'ls' && e.cwd === '/var/log');
          return listed >= 0 && log.slice(listed).some((e) => e.name === 'cd' && e.cwd === '/home/learner');
        } },
        { type: 'predict', question: 'You are in `/home/learner/notes`. Where does `cd ../logs` take you?', options: [
          { text: '`/home/learner/logs`', correct: true, why: '`..` goes up to `/home/learner`, then `logs` goes down into the logs folder there.' },
          { text: '`/home/learner/notes/logs`', why: 'That would be `cd logs`. The `..` first moves you up one level.' },
          { text: '`/logs`', why: 'That would be the absolute path `/logs`. `..` only goes up one level, not to the root.' }
        ] },
        { type: 'order', question: 'You start in `/home/learner/notes`. Put these in the order that ends with you reading the syslog file.', items: ['`cd ..` (now in /home/learner)', '`cd /var/log`', '`ls` to check the file is there', '`cat syslog`'], explain: 'Going up first is not actually needed here, since `cd /var/log` works from anywhere. That is the main advantage of absolute paths.' },
        { type: 'answer', question: 'Which single character stands for your home folder?', accept: ['~'], hint: 'It is the wavy one, usually under Esc on the keyboard.', explain: '`~` expands to your home path. `cd ~/notes` works from anywhere.' },
        { type: 'note', title: 'Tab completion', body: 'Type the first few letters of a file or folder name and press Tab. The shell fills in the rest if there is only one match, or shows you the options. It saves typing and avoids typos. It works in this terminal too.' }
      ]
    },
    {
      id: 'linux-reading',
      title: 'Reading files and hidden files',
      summary: 'cat, head and tail, and why some files do not show up in ls.',
      minutes: 9,
      terms: [
        ['dotfile', 'A file whose name starts with a dot, like `.profile`. ls hides these unless you add `-a`. They are hidden from view, not protected.'],
        ['cat', 'Prints the whole contents of one or more files.'],
        ['head and tail', 'Print the first or last lines of a file, 10 by default. `-n 20` changes the count.']
      ],
      workspace: lessonMachine('Practice machine. Try: cat notes/meeting.txt\n'),
      blocks: [
        { type: 'text', body: '`cat` prints a file. It is the right tool for something short. For a long file, look at a piece of it first with `head` (the start) or `tail` (the end). Logs are written from top to bottom, so the newest entries are at the end, which makes `tail` the usual first look.' },
        { type: 'example', steps: [
          { cmd: 'cat notes/meeting.txt', out: 'Weekly sync, 12 March\n\nPriya: backups are running nightly now.\n...', note: 'Short file, so cat is fine.' },
          { cmd: 'head -n 3 logs/access.log', note: 'First three lines only.' },
          { cmd: 'tail -n 3 logs/access.log', note: 'Last three lines, which are the most recent.' },
          { cmd: 'wc -l logs/access.log', out: '240 logs/access.log', note: '`wc -l` counts lines, so you know how big something is before printing it.' }
        ] },
        { type: 'text', body: 'Linux hides any file or folder whose name begins with a dot. These **dotfiles** usually hold settings, like `.profile` or `.bashrc`. They are not secret in any way; `ls` just leaves them out to keep listings tidy. Add `-a` (all) to see them.' },
        { type: 'predict', question: 'Your home folder contains `notes`, `logs` and `.plan`. What does plain `ls` print?', options: [
          { text: '`logs  notes`', correct: true, why: 'Names starting with a dot are skipped unless you ask for them with `-a`.' },
          { text: '`.plan  logs  notes`', why: 'That is what `ls -a` would show (plus `.` and `..`).' },
          { text: 'Nothing, because hidden files make ls fail', why: 'Hidden files never cause an error. They are simply left out.' }
        ] },
        { type: 'task', text: 'Find the hidden file in your home folder whose name is not `.profile`, and read it.', hint: '`ls -a` lists everything. Then `cat` the one you did not expect.', check: (log) => ran(log, 'cat', (a) => a.includes('.plan')) },
        { type: 'quiz', question: 'Why do so many applications keep their settings in dotfiles, like `.bashrc` or `.gitconfig`?', options: [
          { text: 'So they stay out of the way in normal listings', correct: true, why: 'It is purely about tidiness. That also means a dotfile is not a safe place for anything secret, because anyone who can read the folder can read it with `ls -a`.' },
          { text: 'Because files with a dot cannot be deleted', why: 'Dotfiles can be deleted like any other file.' },
          { text: 'Because the dot encrypts the file', why: 'The name has no effect on the contents or the permissions.' }
        ] },
        { type: 'answer', question: 'Which command shows only the last 5 lines of `logs/auth.log`?', accept: ['tail -n 5 logs/auth.log', 'tail -5 logs/auth.log', 'tail -n5 logs/auth.log'], hint: 'Use tail with `-n` and a number, then the file path.' }
      ]
    },
    {
      id: 'linux-permissions',
      title: 'Users and permissions',
      summary: 'Read the permission string in ls -l, understand owner, group and everyone else, and use chmod.',
      minutes: 14,
      terms: [
        ['permission bits', 'Three sets of read (r), write (w) and execute (x): one for the file owner, one for its group, one for everyone else.'],
        ['chmod', 'Changes a file\'s permissions, for example `chmod 600 file` or `chmod u+x script.sh`. Only the owner or root can do it.'],
        ['root', 'The administrator account, with user id 0. The kernel skips most permission checks for root.'],
        ['execute on a folder', 'For directories, x means you are allowed to go into it and reach the files inside. Without it, you cannot open anything in that folder even if you know the name.'],
        ['octal mode', 'Permissions written as three digits, where read is 4, write is 2 and execute is 1. So 7 is rwx, 6 is rw-, 5 is r-x and 4 is r--.']
      ],
      workspace: lessonMachine('Practice machine. Try: ls -l\n'),
      blocks: [
        { type: 'text', body: 'Every file has an **owner**, a **group**, and three sets of permissions: what the owner can do, what members of the group can do, and what everyone else can do. `ls -l` shows all of it.' },
        { type: 'code', body: '-rw-r--r--  1 learner learner   37 Mar 11 10:00 private.txt\ndrwxr-x---  2 root    staff   4096 Mar 14 10:00 shared', caption: 'Two lines from `ls -l`.' },
        { type: 'table', head: ['Characters', 'Meaning for private.txt'], rows: [['`-`', 'Type: `-` for a file, `d` for a directory'], ['`rw-`', 'Owner (learner) can read and write'], ['`r--`', 'Group (learner) can read'], ['`r--`', 'Everyone else can read'], ['`learner learner`', 'Owner, then group']] },
        { type: 'predict', question: 'Look at `shared` above: `drwxr-x--- root staff`. You are `learner` and not in the staff group. What happens when you run `ls /srv/shared`?', options: [
          { text: 'Permission denied', correct: true, why: 'You are not the owner and not in the group, so the last set applies: `---`. No read, no entry.' },
          { text: 'It lists the files but you cannot open them', why: 'Listing a folder needs read permission on it, and the "everyone else" set has none.' },
          { text: 'It works, because folders are always readable', why: 'Folders have permissions just like files.' }
        ] },
        { type: 'task', text: 'Try to list `/srv/shared` and see the error for yourself. Then run `id` to see which groups you are in.', check: (log) => log.some((e) => e.name === 'ls' && e.args.join(' ').includes('/srv/shared') && e.exit !== 0) && ran(log, 'id') },
        { type: 'text', body: 'Permissions are often written as three digits. Each digit adds up read (4), write (2) and execute (1). So `rw-` is 4 + 2 = 6, `r-x` is 4 + 1 = 5, and `rwx` is 7.' },
        { type: 'table', head: ['Mode', 'String', 'Typical use'], rows: [['`644`', '`rw-r--r--`', 'Normal file: you edit, others read'], ['`600`', '`rw-------`', 'Private file, like an SSH key'], ['`755`', '`rwxr-xr-x`', 'Program or folder others can use'], ['`700`', '`rwx------`', 'Private folder'], ['`777`', '`rwxrwxrwx`', 'Anyone can do anything. Almost always a mistake']] },
        { type: 'answer', question: 'What three-digit mode gives the owner read and write, and nobody else anything?', accept: ['600', '0600'], explain: 'Owner 6 (4 + 2), group 0, others 0. This is the mode SSH insists on for private keys.' },
        { type: 'task', text: '`private.txt` is currently readable by everyone. Change it so only you can read and write it, then check with `ls -l`.', hint: '`chmod 600 private.txt`', check: (log, ws) => ws.fs && (ws.fs.lookup('/home/learner/private.txt').mode & 0o777) === 0o600 },
        { type: 'note', title: 'Root', body: 'The root user skips nearly every permission check, which is why administrators use it sparingly and why protecting it matters so much. On most systems you never log in as root directly; you run single commands with administrator rights only when you need them.' },
        { type: 'quiz', question: 'A folder is `drwxr--r--` and owned by someone else. You can see its file names with ls, but `cat` on a file inside fails. Why?', options: [
          { text: 'You have read on the folder but not execute, so you cannot reach the files', correct: true, why: 'On a folder, r lets you list names and x lets you go in and use what is inside. You need x to open any file in it.' },
          { text: 'The files inside must all be mode 000', why: 'They might be readable. The folder is stopping you before the file permissions even matter.' },
          { text: 'cat only works on files you own', why: 'cat works on any file you have read permission for.' }
        ] }
      ]
    },
    {
      id: 'linux-search',
      title: 'Finding files and text',
      summary: 'Use find to locate files by name, size or owner, and grep to find lines inside them.',
      minutes: 13,
      terms: [
        ['find', 'Walks a folder tree and prints every path that passes your tests, such as `-name`, `-type f`, `-size` or `-user`.'],
        ['grep', 'Prints the lines that match a pattern. `-r` searches a whole folder, `-i` ignores case, `-n` adds line numbers, `-v` prints lines that do not match.'],
        ['2>/dev/null', 'Sends error messages to nowhere. Handy with find, which prints "Permission denied" for every folder it cannot enter.'],
        ['regular expression', 'A pattern language for text. In grep, `.` matches any character, `*` repeats the previous thing, `^` is the start of a line and `$` is the end.']
      ],
      workspace: lessonMachine('Practice machine. Try: grep -n "Failed" logs/auth.log\n'),
      blocks: [
        { type: 'text', body: 'Two commands do most of the searching on a Linux box. **find** answers "where is the file?" and **grep** answers "which line says that?"' },
        { type: 'example', title: 'find', steps: [
          { cmd: 'find . -name "*.txt"', note: 'Every file below the current folder whose name ends in .txt. Quote the pattern so the shell passes the star to find untouched.' },
          { cmd: 'find / -name "*.log" 2>/dev/null', note: 'Search the whole system. `2>/dev/null` hides the permission errors.' },
          { cmd: 'find /home -type f -size +1k', note: '`-type f` means files only, `-size +1k` means bigger than 1 KB. Use `c` for exact bytes, like `-size 1337c`.' },
          { cmd: 'find / -user priya 2>/dev/null', note: 'Everything owned by a particular user.' }
        ] },
        { type: 'task', text: 'Use find to list every `.log` file on the system, with the permission errors hidden.', hint: 'Start at `/`, use `-name "*.log"`, and add `2>/dev/null`.', check: (log) => log.some((e) => e.name === 'find' && /\.log/.test(e.args.join(' '))) },
        { type: 'example', title: 'grep', steps: [
          { cmd: 'grep "Failed" logs/auth.log', note: 'Every line containing Failed.' },
          { cmd: 'grep -i "failed" logs/auth.log', note: '`-i` ignores upper and lower case.' },
          { cmd: 'grep -rn "TODO" projects/', note: '`-r` searches all files in a folder, `-n` shows line numbers.' },
          { cmd: 'grep -v " 200 " logs/access.log', note: '`-v` flips it: lines that do not contain " 200 ", so everything except successful requests.' }
        ] },
        { type: 'predict', question: 'What does `grep -c "401" logs/access.log` print?', options: [
          { text: 'A single number: how many lines contain 401', correct: true, why: '`-c` counts matching lines instead of printing them.' },
          { text: 'Every line containing 401', why: 'That is grep without `-c`.' },
          { text: 'The first 401 lines', why: 'That would be `head -n 401`.' }
        ] },
        { type: 'task', text: 'Find the comment someone left in the website project that mentions a test account.', hint: 'Search the `projects` folder recursively for the word "test", ignoring case.', check: (log) => ran(log, 'grep', (a) => /-\w*r/.test(a) || /index\.html/.test(a)) },
        { type: 'spot', question: 'This command is meant to find every file containing the word password under /etc, but it prints nothing useful. Which line is the problem?', code: 'cd /etc\ngrep password\nls -la', line: 2, explain: 'Without a file name, grep waits to read from the keyboard (stdin) and never looks at any files. It needs `-r password .` or a file list.', nudge: 'Think about what grep searches when you do not give it anything to search.' },
        { type: 'quiz', question: 'You want every file under /home that is owned by tom. Which command fits?', options: [
          { text: '`find /home -user tom`', correct: true },
          { text: '`grep -r tom /home`', why: 'That finds files whose text mentions tom, which is a different question.' },
          { text: '`ls -l /home | grep tom`', why: 'Close, but it only looks at the top level of /home, not the files inside each folder.' }
        ] }
      ]
    },
    {
      id: 'linux-pipes',
      title: 'Pipes and redirection',
      summary: 'Join small commands into one line that answers a real question, and save the result to a file.',
      minutes: 14,
      terms: [
        ['pipe', 'The `|` symbol. It sends the output of the command on the left into the command on the right.'],
        ['redirection', '`>` writes a command\'s output to a file, replacing it. `>>` adds to the end instead. `<` feeds a file in as input.'],
        ['sort | uniq -c', 'The classic counting combo. sort puts identical lines next to each other, then uniq -c collapses them and counts each one.'],
        ['cut', 'Takes columns out of each line. `cut -d" " -f1` splits on spaces and keeps the first field.']
      ],
      workspace: lessonMachine('Practice machine. Try: cat logs/access.log | head -3\n'),
      blocks: [
        { type: 'text', body: 'Linux tools are deliberately small. Each one does one job and reads text in and writes text out. The **pipe** `|` connects them, so the output of one becomes the input of the next. With five or six small tools you can answer questions that would otherwise need a script.' },
        { type: 'text', body: 'Here is a question from the meeting notes: **which IP address made the most requests?** Each line of `logs/access.log` starts with an IP. Build the answer one step at a time and look at the output after each step.' },
        { type: 'example', title: 'Building a pipeline', steps: [
          { cmd: 'head -n 2 logs/access.log', note: 'Look at the data first. The IP is the first space-separated field.' },
          { cmd: 'cut -d" " -f1 logs/access.log | head -n 3', note: 'Keep only field 1.' },
          { cmd: 'cut -d" " -f1 logs/access.log | sort | uniq -c', note: 'Sort so identical IPs sit together, then count each run.' },
          { cmd: 'cut -d" " -f1 logs/access.log | sort | uniq -c | sort -rn | head -n 1', note: 'Sort the counts numerically, biggest first, and keep the top line.' }
        ] },
        { type: 'order', question: 'Put the stages in order to count how many requests got each status code (the 9th field).', items: ['`cut -d" " -f9 logs/access.log`', '`sort`', '`uniq -c`', '`sort -rn`'], explain: 'Extract, group, count, rank. You will use this shape again and again.' },
        { type: 'task', text: 'Run a pipeline that shows the number of requests per IP address, busiest first.', hint: 'The last example above does it. Try typing it yourself rather than copying.', check: (log) => log.some((e) => e.name === 'uniq' && e.args.includes('-c') && e.exit === 0) },
        { type: 'text', body: '**Redirection** saves output instead of printing it. `>` creates or replaces a file. `>>` appends to it. Be careful with `>`: pointing it at the wrong file wipes that file before the command even runs.' },
        { type: 'example', steps: [
          { cmd: 'grep " 401 " logs/access.log > failed.txt', note: 'Save the failed logins to a file.' },
          { cmd: 'wc -l failed.txt', note: 'Count them.' },
          { cmd: 'echo "checked by learner" >> failed.txt', note: 'Add a line at the end without losing what is there.' }
        ] },
        { type: 'task', text: 'Save every line of `logs/access.log` that contains ` 401 ` into a file called `failed.txt` in your home folder.', check: (log, ws) => {
          try {
            const text = new TextDecoder().decode(ws.fs.readFile('/home/learner/failed.txt', 'learner'));
            return text.includes(' 401 ') && !text.includes(' 200 ');
          } catch {
            return false;
          }
        } },
        { type: 'predict', question: 'What is in `out.txt` after these two commands?', code: 'echo one > out.txt\necho two > out.txt', options: [
          { text: 'Just `two`', correct: true, why: 'A single `>` replaces the file each time. Use `>>` to keep both.' },
          { text: '`one` then `two`', why: 'That needs `>>` on the second line.' },
          { text: 'An error because the file already exists', why: 'The shell overwrites without asking. That is exactly why it is dangerous.' }
        ] }
      ]
    },
    {
      id: 'linux-files',
      title: 'Looking inside files',
      summary: 'Identify a file by its contents, pull readable text out of binaries, and read raw bytes in hex.',
      minutes: 12,
      terms: [
        ['magic bytes', 'The first few bytes of a file that identify its format, like `89 50 4E 47` for PNG. The `file` command reads these instead of trusting the name.'],
        ['strings', 'Prints every run of readable characters in a file. A fast first look inside a program or unknown blob.'],
        ['hex dump', 'A view of a file as raw byte values in hexadecimal, usually with the printable characters alongside. `xxd` makes one.'],
        ['Base64', 'A way to write any bytes using only letters, digits, + and /. Common in emails, web tokens and config files. It is not encryption.']
      ],
      workspace: lessonMachine('Practice machine. Try: file evidence/*\n'),
      blocks: [
        { type: 'text', body: 'File extensions are just part of the name. Anyone can call a picture `report.txt`. To know what a file really is, look at its first bytes. Most formats start with a fixed signature, called **magic bytes**, and the `file` command checks them for you.' },
        { type: 'example', steps: [
          { cmd: 'file evidence/report.txt', out: 'evidence/report.txt: PNG image data, ...', note: 'Despite the name, this is an image.' },
          { cmd: 'xxd evidence/report.txt | head -n 2', out: '00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR', note: 'The first eight bytes are the PNG signature. Left column is the offset, middle is the bytes in hex, right is any printable characters.' }
        ] },
        { type: 'table', head: ['Starts with', 'Format'], rows: [['`89 50 4E 47`', 'PNG image'], ['`FF D8 FF`', 'JPEG image'], ['`25 50 44 46` (%PDF)', 'PDF'], ['`50 4B 03 04` (PK)', 'ZIP, and also .docx, .xlsx, .jar and .apk'], ['`7F 45 4C 46` (.ELF)', 'Linux program'], ['`4D 5A` (MZ)', 'Windows program']] },
        { type: 'task', text: 'Find out what kind of file `evidence/firmware.bin` really is.', check: (log) => ran(log, 'file', (a) => a.includes('firmware') || a.includes('*')) },
        { type: 'text', body: 'Programs and firmware are mostly unreadable bytes, but they often carry text inside: error messages, URLs, user names, and sometimes passwords someone forgot to remove. `strings` pulls those out.' },
        { type: 'task', text: 'Use strings on the firmware and pipe it into grep to find the admin user name it contains.', hint: '`strings evidence/firmware.bin | grep admin`', check: (log) => ran(log, 'strings', (a) => a.includes('firmware')) },
        { type: 'text', body: 'Finally, **Base64**. You will see it everywhere: long strings of letters and digits, often ending in `=`. It turns bytes into safe printable text so they survive email or URLs. Decoding needs no key, so it hides nothing.' },
        { type: 'example', steps: [
          { cmd: 'echo -n "hi" | base64', out: 'aGk=' },
          { cmd: 'cat evidence/message.b64 | base64 -d', note: '`-d` decodes.' }
        ] },
        { type: 'task', text: 'Decode `evidence/message.b64` and read what it says.', check: (log) => ran(log, 'base64', (a) => a.includes('-d')) },
        { type: 'quiz', question: 'A file named `invoice.pdf` starts with the bytes `4D 5A`. What should you conclude?', options: [
          { text: 'It is a Windows program pretending to be a PDF', correct: true, why: '`MZ` is the start of every Windows executable. Fake extensions and icons are a common trick in phishing attachments, which is why mail filters check the real type.' },
          { text: 'It is a damaged PDF', why: 'A real PDF starts with `%PDF`. This is a completely different format.' },
          { text: 'Nothing, extensions are what matter', why: 'Extensions are only names. The bytes decide what the file is.' }
        ] }
      ]
    }
  ],
  challenges: [
    {
      id: 'linux-hidden-note',
      title: 'Left behind',
      difficulty: 'easy',
      points: 50,
      skills: ['ls -a', 'cat', 'cd'],
      prepare: ['linux-paths', 'linux-reading'],
      brief: 'A contractor finished a job on this server and said they left the handover details "somewhere obvious" in their project folder. You can see the folder, but it looks empty.',
      goal: 'Find the handover note and submit the flag inside it.',
      flag: 'yyBckgScOkbSkMP7sYtYBGgSGYcf2Dg6ISPea/sKisPhfRSwAw==',
      workspace: (flag) => ({
        type: 'shell',
        motd: 'Server: build-02. The contractor project lives in /srv/projects/handover.\n',
        files: {
          '/srv/projects/handover/': {},
          '/srv/projects/handover/.handover': `Handover from Dee\n\n- Deploy key rotated on Monday\n- Build cache cleared\n- Flag for whoever finds this: ${flag}\n`,
          '/srv/projects/README.md': 'Each contractor gets a folder here.\n',
          '/home/learner/welcome.txt': 'Start in /srv/projects.\n'
        }
      }),
      hints: ['An empty-looking folder is not always empty. What does `ls` leave out by default?', 'Files whose names start with a dot are hidden from a plain `ls`. Add an option to show everything.', 'Run `ls -a /srv/projects/handover`, then `cat` the file you find.'],
      writeup: {
        how: 'The note was called `.handover`. Because the name starts with a dot, `ls` skips it. `ls -a` shows all names, including dotfiles, and `cat` reads it.',
        why: 'Dotfiles are where configuration and credentials tend to pile up: `.env` files with database passwords, `.git` folders with a project\'s full history, cloud credential files. Anyone auditing a server checks for them early.',
        fix: 'Hidden is not protected. Anything sensitive needs real permissions (for example `chmod 600`) or should not be on the server at all.'
      }
    },
    {
      id: 'linux-needle',
      title: 'Needle in the logs',
      difficulty: 'easy',
      points: 100,
      skills: ['grep -r', 'logs'],
      prepare: ['linux-search'],
      brief: 'A web app writes logs for six services into `/var/log/app`, and there are thousands of lines. One of the debug lines printed a flag by mistake. Reading every file by hand would take an hour.',
      goal: 'Search the logs and submit the flag that leaked into them.',
      flag: '0oVMplrkZaSQND0epHSKKSNM0eDDvxKGL4/v',
      workspace: (flag) => {
        const r = random(41);
        const services = ['auth', 'billing', 'search', 'gateway', 'mailer', 'worker'];
        const levels = ['INFO', 'INFO', 'INFO', 'DEBUG', 'WARN'];
        const messages = ['request handled in %dms', 'cache hit for key user:%d', 'queue depth %d', 'retrying job %d', 'connection pool size %d', 'health check ok (%dms)'];
        const files = {};
        services.forEach((service) => {
          const lines = [];
          for (let i = 0; i < 400; i++) {
            lines.push(`2026-03-13T06:${String(Math.floor(i / 7) % 60).padStart(2, '0')}:${String((i * 13) % 60).padStart(2, '0')}Z ${r.pick(levels)} ${service} ${r.pick(messages).replace('%d', r.int(1, 999))}`);
          }
          const rotated = lines.slice(0, 120).map((l) => l.replace('2026-03-13', '2026-03-12'));
          if (service === 'billing') lines.splice(287, 0, `2026-03-13T06:41:08Z DEBUG billing dumping config: currency=EUR retries=3 debug_token=${flag}`);
          files[`/var/log/app/${service}/${service}.log`] = lines.join('\n') + '\n';
          files[`/var/log/app/${service}/${service}.log.1`] = rotated.join('\n') + '\n';
        });
        return { type: 'shell', motd: 'Logs are in /var/log/app, one folder per service.\n', cwd: '/var/log/app', files };
      },
      hints: ['You do not need to read the files. Search them.', 'Every flag starts with `HW{`. grep can search a whole folder tree with one option.', 'Run `grep -r "HW{" /var/log/app`.'],
      writeup: {
        how: '`grep -r` walks every file under a folder and prints matching lines with the file name in front. Searching for the flag prefix finds the one debug line in the billing log that dumped a token.',
        why: 'Secrets leaking into logs is extremely common: tokens in debug output, passwords in URLs, API keys in stack traces. Logs are usually readable by far more people and systems than the secret was meant for, and they are often shipped off to third party services.',
        fix: 'Do not log full configuration or request bodies. Use logging libraries that redact known secret fields, keep debug logging off in production, and treat log storage as sensitive.'
      }
    },
    {
      id: 'linux-exact-size',
      title: 'Exactly 1,337 bytes',
      difficulty: 'easy',
      points: 100,
      skills: ['find -size', 'find -type'],
      prepare: ['linux-search'],
      brief: 'The backup folder has hundreds of files with meaningless names. The admin remembers only one detail about the file they need: it was exactly 1,337 bytes.',
      goal: 'Find the file that is exactly 1,337 bytes and submit the flag inside.',
      flag: 'L9LIxi8Uq/RouM5Nf4W3xOliIX/lvg==',
      workspace: (flag) => {
        const r = random(1337);
        const files = {};
        const word = () => r.pick(['alpha', 'bravo', 'delta', 'echo', 'kilo', 'lima', 'oscar', 'tango', 'zulu']);
        const filler = (n) => {
          let s = '';
          while (s.length < n) s += `${word()} ${word()} ${r.int(1000, 9999)}\n`;
          return s.slice(0, n);
        };
        for (let i = 0; i < 180; i++) {
          let size = r.int(200, 3000);
          if (size === 1337) size = 1338;
          const dir = `/srv/backup/${r.pick(['daily', 'weekly', 'adhoc'])}/${r.int(10, 99)}`;
          files[`${dir}/${r.int(100000, 999999).toString(36)}.dat`] = filler(size);
        }
        const header = `restore notes\n${flag}\n`;
        files['/srv/backup/weekly/42/k3x9q1.dat'] = header + filler(1337 - header.length);
        files['/srv/backup/adhoc/17/zz00a1.dat'] = 'restore notes\nthis is a decoy, keep looking\n' + filler(1100);
        return { type: 'shell', cwd: '/srv/backup', motd: 'Backup store. Hundreds of files, one of them exactly 1337 bytes.\n', files };
      },
      hints: ['find can filter by size as well as by name.', 'The `-size` test takes a unit. `c` means bytes.', 'Run `find /srv/backup -type f -size 1337c`, then cat what it prints.'],
      writeup: {
        how: '`find /srv/backup -type f -size 1337c` checks every file and prints only those with exactly 1,337 bytes. Without the `c` suffix, find counts in 512-byte blocks, which is a common surprise.',
        why: 'find can filter on size, owner, permissions and modification time, which makes it a key tool in incident response. "Every file changed in the last day" (`-mtime -1`) or "every file owned by the web server user" (`-user www-data`) are questions you will ask for real.'
      }
    },
    {
      id: 'linux-locked-out',
      title: 'Locked out of your own file',
      difficulty: 'medium',
      points: 150,
      skills: ['ls -l', 'chmod', 'permissions'],
      prepare: ['linux-permissions'],
      brief: 'A cleanup script went wrong and set the permissions on everything in your vault folder to nothing at all. The files are still yours, but `cat` says "Permission denied" on all of them.',
      goal: 'Get the flag out of `~/vault/key.txt`.',
      flag: 'Xjewm492U7zUBY/F+YNjtaYzfXmKFoueQZ0f',
      workspace: (flag) => ({
        type: 'shell',
        motd: 'Your vault is in ~/vault. Something is wrong with it.\n',
        users: [{ name: 'priya', uid: 1001 }],
        files: {
          '/home/learner/vault/': { mode: 0o755 },
          '/home/learner/vault/key.txt': { content: `${flag}\n`, mode: 0o000 },
          '/home/learner/vault/notes.txt': { content: 'Remember: rotate the key on the first of every month.\n', mode: 0o000 },
          '/home/learner/vault/shared-key.txt': { content: 'This one belongs to priya.\n', mode: 0o000, owner: 'priya' }
        }
      }),
      hints: ['Start with `ls -l ~/vault`. Who owns key.txt, and what are its permissions?', 'You are the owner. The owner of a file can always change its permissions, even when they are all off.', 'Run `chmod 600 ~/vault/key.txt` (or `chmod u+r`), then `cat` it.'],
      writeup: {
        how: '`ls -l` shows `----------` and owner `learner`. With no read bit you cannot open the file, but as the owner you can still run `chmod` on it. `chmod 600` restores read and write for you, and then `cat` works. The file owned by priya cannot be fixed this way, because only the owner or root may change permissions.',
        why: 'Permission problems are behind a large share of both outages and data leaks. Reading `ls -l` quickly, and knowing who is allowed to change what, is basic to running any server.',
        fix: 'Scripts that change permissions in bulk should be tested on copies, and should set explicit modes rather than computing them.'
      }
    },
    {
      id: 'linux-top-talker',
      title: 'Who keeps trying?',
      difficulty: 'medium',
      points: 150,
      skills: ['cut', 'sort', 'uniq -c', 'pipes'],
      prepare: ['linux-pipes'],
      brief: 'The login page is getting hammered. `/var/log/nginx/access.log` has a few thousand requests from dozens of addresses. Failed logins show up as `POST /login` with status `401`.\n\nYou need to name the single address responsible for the most failed logins, and how many it made, so the team can block it.',
      goal: 'Submit `HW{ip_count}`, for example `HW{192.0.2.1_57}`, using the IP with the most 401 responses and its exact count.',
      flag: 'Z+rmWE5Ib1oRYGvmP0uvuqbCJjTy',
      workspace: () => {
        const r = random(9001);
        const pool = Array.from({ length: 40 }, () => `${r.pick([10, 172, 192, 198, 203])}.${r.int(0, 255)}.${r.int(0, 255)}.${r.int(1, 254)}`);
        const noisy = '198.51.100.77', close = '203.0.113.40';
        const lines = [];
        let t = 0;
        const add = (ip, method, path, status) => lines.push(`${ip} - - [${clf((t += r.int(1, 9)))}] "${method} ${path} HTTP/1.1" ${status} ${r.int(200, 4000)} "-" "Mozilla/5.0"`);
        for (let i = 0; i < 2600; i++) {
          const ip = r.pick(pool);
          if (r.next() < 0.15) add(ip, 'POST', '/login', r.next() < 0.5 ? 401 : 302);
          else add(ip, 'GET', r.pick(['/', '/products', '/cart', '/static/site.css', '/login']), r.next() < 0.03 ? 404 : 200);
          if (i % 7 === 0) add(noisy, 'POST', '/login', 401);
          if (i % 9 === 0) add(close, 'POST', '/login', 401);
          if (i % 5 === 0) add(close, 'GET', '/products', 200);
        }
        add(noisy, 'POST', '/login', 302);
        return { type: 'shell', motd: 'Web server logs are in /var/log/nginx.\n', cwd: '/var/log/nginx', files: { '/var/log/nginx/access.log': lines.join('\n') + '\n' } };
      },
      hints: ['First narrow the log down to failed logins only, then count per IP.', 'grep for `" 401 "` (with the spaces) so you match the status column, then take the first field with cut.', '`grep " 401 " access.log | cut -d" " -f1 | sort | uniq -c | sort -rn | head -n 3`'],
      writeup: {
        how: 'Filter, extract, group, count, rank: `grep " 401 " access.log | cut -d" " -f1 | sort | uniq -c | sort -rn | head`. The top line gives both the address and its count. Another address is busier overall, but most of its traffic is ordinary page views, which is why counting every request instead of only the failures gives the wrong answer.',
        why: 'This is how analysts spot password guessing, scanners and misbehaving clients, and the same pattern answers questions like "which user agent is most common" or "which pages return errors". On a real incident you might run it against millions of lines.',
        fix: 'Rate limit login attempts per IP and per account, slow down or lock accounts after repeated failures, and alert on spikes in 401 responses.'
      }
    },
    {
      id: 'linux-firmware',
      title: 'Strings attached',
      difficulty: 'medium',
      points: 150,
      skills: ['file', 'strings', 'grep', 'base64 -d'],
      prepare: ['linux-files'],
      brief: 'You have a firmware image from a cheap network camera that your company is thinking of buying in bulk. Before anyone signs, you have been asked to check whether the vendor left anything sensitive inside. Rumour says there is a support key baked in, but it is not stored as plain text.',
      goal: 'Find the support key in `camera.bin`, decode it, and submit the flag.',
      flag: 'DzDGj3H8RYmI2AQNV+xxNJu8Na7gx/NbnFaUQAimWA==',
      workspace: (flag) => ({
        type: 'shell',
        motd: 'Firmware dump: ~/camera.bin\n',
        files: {
          '/home/learner/camera.bin': binaryWith([
            'U-Boot 2019.04 (Jun 02 2024)', 'Linux version 4.9.37', 'rtsp://0.0.0.0:554/stream1',
            'default_user=admin', 'default_pass=admin', 'cloud_host=cam-relay.example.com', `support_key=${toBase64(utf8(flag))}`,
            'ERROR: sensor not found', 'Copyright (c) 2024 Example Vision'
          ], 77, 6000)
        }
      }),
      hints: ['Start with `file camera.bin`, then pull out the readable text.', '`strings camera.bin | grep -i key` narrows it down. The value after the equals sign looks like Base64.', 'Copy the value and run `echo <value> | base64 -d`.'],
      writeup: {
        how: '`strings` lists the readable text in the binary. Filtering for "key" shows `support_key=` followed by a Base64 string. `base64 -d` decodes it to the flag. You may also have noticed `default_pass=admin`, which is the kind of finding that should stop a purchase.',
        why: 'Hardcoded and default credentials in firmware are one of the most common findings in device security reviews. Large botnets have spread simply by trying factory default passwords against internet-connected devices.',
        fix: 'Do not ship shared secrets in firmware. Generate per-device credentials, force a password change on first use, and do not mistake encoding for protection.'
      }
    },
    {
      id: 'linux-history',
      title: 'What they typed',
      difficulty: 'medium',
      points: 200,
      skills: ['.bash_history', 'ls -a', 'investigation'],
      prepare: ['linux-reading', 'linux-search'],
      brief: 'A confidential report has gone missing from `/srv/reports`. The only person who touched that folder recently is `jordan`, and the original file has been deleted. Bash saves the commands each user types to a file in their home folder, and on this badly configured server, everyone can read everyone else\'s.',
      goal: 'Work out where the report went and submit the flag inside it.',
      flag: 'KywxaGp9c85pe/KxBS/wQpim06m78KZbiif/1r1DZHo71/Zy',
      workspace: (flag) => ({
        type: 'shell',
        motd: 'Users on this machine have folders under /home.\n',
        users: [{ name: 'jordan', uid: 1003 }],
        files: {
          '/home/jordan/': { owner: 'jordan', mode: 0o755 },
          '/home/jordan/todo.txt': { content: 'finish Q3 numbers\nsend report to finance\n', owner: 'jordan' },
          '/home/jordan/.bash_history': { owner: 'jordan', mode: 0o644, content: [
            'ls', 'cd /srv/reports', 'ls -la', 'cat q3-final.txt | head', 'mkdir -p /tmp/.cache-7f3a', 'cp q3-final.txt /tmp/.cache-7f3a/', 'rm q3-final.txt', 'cd', 'history -c', 'exit'
          ].join('\n') + '\n' },
          '/srv/reports/': {},
          '/srv/reports/q2-final.txt': 'Q2 report: revenue up 4%.\n',
          '/tmp/.cache-7f3a/': { owner: 'jordan', mode: 0o755 },
          '/tmp/.cache-7f3a/q3-final.txt': { owner: 'jordan', mode: 0o644, content: `Q3 FINAL (confidential)\nRevenue down 11%.\n${flag}\n` },
          '/tmp/systemd-private-1a2b/': { mode: 0o700 }
        }
      }),
      hints: ['Look in /home/jordan, including hidden files.', 'Bash writes history to `~/.bash_history`. jordan ran `history -c`, but that only clears the history in memory, not the file already saved.', 'Read `/home/jordan/.bash_history`, then follow the `cp` command to its destination.'],
      writeup: {
        how: 'jordan\'s `.bash_history` was readable by everyone (mode 644). It shows the report being copied to `/tmp/.cache-7f3a/` before the original was deleted. That folder is hidden by its leading dot, but `cat /tmp/.cache-7f3a/q3-final.txt` works.',
        why: 'Shell history is one of the first things an investigator reads, because it shows exactly what happened and in what order. It also tends to collect things that should never be stored, like passwords typed as command arguments. `history -c` does not erase what was already written to disk.',
        fix: 'Keep home folders and history files private (700 and 600). Never put secrets in command arguments, since they also appear in process lists. Shared machines should not let users read each other\'s files.'
      }
    },
    {
      id: 'linux-groups',
      title: 'Members only',
      difficulty: 'medium',
      points: 200,
      skills: ['id', 'groups', 'find -group', 'permissions'],
      prepare: ['linux-permissions', 'linux-search'],
      brief: 'You have just joined the audit team and been added to a group on this server, but nobody told you which folders it opens up. Somewhere on the system is a folder only that group can read.',
      goal: 'Find the folder your group gives you access to and submit the flag stored there.',
      flag: 'xarliobJHNGM/Y3IYY1w2IoPhzm7WL1AoSVDxoU=',
      workspace: (flag) => ({
        type: 'shell',
        motd: 'Welcome to the team. You now have extra access on this machine.\n',
        learnerGroups: ['auditors'],
        users: [{ name: 'sam', uid: 1004, groups: ['sam', 'auditors'] }],
        files: {
          '/opt/finance/': { mode: 0o750, group: 'finance' },
          '/opt/finance/ledger.csv': { mode: 0o640, group: 'finance', content: 'not for you\n' },
          '/var/audit/': { mode: 0o750, group: 'auditors' },
          '/var/audit/2026/': { mode: 0o750, group: 'auditors' },
          '/var/audit/2026/march.txt': { mode: 0o640, group: 'auditors', content: `Audit trail, March\nAll admin logins reviewed. ${flag}\n` },
          '/srv/hr/': { mode: 0o700, owner: 'root' },
          '/srv/hr/salaries.csv': 'not for you\n',
          '/home/learner/onboarding.txt': 'You were added to a new group today. Ask the system which one.\n'
        }
      }),
      hints: ['Start by asking the system who you are and which groups you belong to.', '`id` lists your groups. Then search the whole filesystem for things that belong to that group.', '`find / -group auditors 2>/dev/null`, then read the file you find.'],
      writeup: {
        how: '`id` shows you are in `auditors`. `find / -group auditors 2>/dev/null` lists `/var/audit` and the file inside it. The folder is `rwxr-x---` with group auditors, so as a group member you can enter and read it.',
        why: 'Group membership quietly grants access, and people collect groups over time without anyone reviewing them. Knowing exactly what an account can reach is the core of an access review.',
        fix: 'Review group membership regularly, give each group the smallest access it needs, and remove people from groups when their role changes.'
      }
    },
    {
      id: 'linux-layers',
      title: 'Wrapped three times',
      difficulty: 'hard',
      points: 250,
      skills: ['xxd -r -p', 'rev', 'base64 -d', 'pipes'],
      prepare: ['linux-files', 'linux-pipes'],
      brief: 'A script on this server stores a note in `~/blob.txt`. It was not encrypted, only transformed several times in a row, and nobody wrote down which transformations or in what order.\n\nEach layer leaves clues in what the data looks like. Work out the outermost layer, undo it, look again, and repeat.',
      goal: 'Undo every layer of `blob.txt` and submit the flag.',
      flag: 'u/CI4aVHXPp60zRdwOD3NssPr03W61xSvGlDITJO6+c=',
      workspace: (flag) => {
        const b64 = toBase64(utf8(flag));
        const reversed = [...b64].reverse().join('');
        const hex = toHex(utf8(reversed));
        return {
          type: 'shell',
          motd: 'The note is in ~/blob.txt. Look at it carefully before decoding anything.\n',
          files: { '/home/learner/blob.txt': hex + '\n' }
        };
      },
      hints: ['Look at which characters appear in `blob.txt`. Only 0 to 9 and a to f means it is probably hex.', '`xxd -r -p` turns plain hex back into bytes. The result looks like Base64, but the `=` padding is at the wrong end.', '`cat blob.txt | xxd -r -p | rev | base64 -d`'],
      writeup: {
        how: 'The file contains only the characters 0 to 9 and a to f, so the outer layer is hex. `xxd -r -p` converts it back to bytes, which gives something that looks like Base64 except that the `=` padding sits at the start. That means it was reversed, so `rev` puts it the right way round, and `base64 -d` gives the flag. The whole thing fits in one pipeline: `cat blob.txt | xxd -r -p | rev | base64 -d`.',
        why: 'Malware, phishing pages and leaked configs often stack simple encodings to get past keyword filters. Recognising each layer by its shape (hex alphabet, Base64 alphabet and padding, reversed text) lets you peel them without guessing.',
        fix: 'Stacking encodings adds no security, because every step is reversible without a key. Data that needs to stay secret needs real encryption with a protected key.'
      }
    }
  ]
};
