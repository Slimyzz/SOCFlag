import { random, at, queried } from './helpers.js';

// Case studies of well known vulnerabilities, told from the defender's side:
// what went wrong in plain terms, the timeline, the impact, how defenders
// noticed and scoped it, and how it was fixed. Every piece of evidence here
// is synthetic and described at the level of a detection (a signature name, a
// firewall decision, a scan result), never as an exploit payload.

const nvd = (id) => `[${id} on the NVD](https://nvd.nist.gov/vuln/detail/${id})`;
const KEV_LINK = '[CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)';

// A small extract of real entries from the CISA KEV catalog. Only identifiers
// and product names, which is public reference data.
const KEV = [
  ['CVE-2014-0160', 'OpenSSL', 'OpenSSL Heartbeat (Heartbleed)'],
  ['CVE-2014-6271', 'GNU', 'Bash (Shellshock)'],
  ['CVE-2017-0144', 'Microsoft', 'SMBv1 (EternalBlue)'],
  ['CVE-2019-0708', 'Microsoft', 'Remote Desktop Services (BlueKeep)'],
  ['CVE-2020-1472', 'Microsoft', 'Netlogon (Zerologon)'],
  ['CVE-2021-26855', 'Microsoft', 'Exchange Server (ProxyLogon)'],
  ['CVE-2021-34527', 'Microsoft', 'Windows Print Spooler (PrintNightmare)'],
  ['CVE-2021-44228', 'Apache', 'Log4j2 (Log4Shell)'],
  ['CVE-2022-30190', 'Microsoft', 'Windows Support Diagnostic Tool (Follina)'],
  ['CVE-2023-23397', 'Microsoft', 'Outlook'],
  ['CVE-2023-34362', 'Progress', 'MOVEit Transfer'],
  ['CVE-2023-4966', 'Citrix', 'NetScaler ADC and Gateway (CitrixBleed)'],
  ['CVE-2024-3400', 'Palo Alto Networks', 'PAN-OS']
];

function csv(rows) {
  return rows.map((row) => row.join(',')).join('\n') + '\n';
}

function kevCsv(entries = KEV) {
  return csv([['cveID', 'vendorProject', 'product'], ...entries]);
}

// A vulnerability scan export. Most rows use invented 2026 identifiers that are
// not in KEV; `plants` adds specific [host, facing, cve] rows on top.
function scanCsv(seed, { count = 40, plants = [] } = {}) {
  const r = random(seed);
  const rows = [['host', 'ip', 'internet_facing', 'cve', 'cvss']];
  const names = ['web', 'app', 'db', 'file', 'mail', 'vpn', 'print', 'dev', 'wiki', 'ad'];
  for (let i = 0; i < count; i++) {
    const host = `${r.pick(names)}${String(i + 1).padStart(2, '0')}`;
    const ip = `10.0.${r.int(1, 9)}.${r.int(10, 250)}`;
    const facing = r.next() < 0.18 ? 'yes' : 'no';
    for (let k = 0; k < r.int(1, 4); k++) rows.push([host, ip, facing, `CVE-2026-${r.int(10000, 49999)}`, (r.int(40, 98) / 10).toFixed(1)]);
  }
  for (const [host, ip, facing, cve, cvss] of plants) rows.push([host, ip, facing, cve, cvss]);
  return csv(rows);
}

// ------------------------------------------------------------ SIEM builders

function idsEvent(time, { signature, cve, src_ip, dest_host, dest_ip, severity = 'high', action = 'detected' }) {
  return {
    _time: time, index: 'ids', sourcetype: 'suricata', signature, cve, src_ip, dest_host, dest_ip, severity, action,
    _raw: `${new Date(time).toISOString().replace('.000', '')} [${action}] ${severity} "${signature}" ${src_ip} -> ${dest_host} ${cve}`
  };
}

function fwEvent(time, { src_host, src_ip, dest_ip, dest_host, dest_port, action = 'allowed' }) {
  return {
    _time: time, index: 'firewall', sourcetype: 'firewall', src_host, src_ip, dest_ip, dest_host, dest_port, action,
    _raw: `${new Date(time).toISOString().replace('.000', '')} ${action.toUpperCase()} ${src_host ?? src_ip} -> ${dest_ip ?? dest_host}:${dest_port}`
  };
}

// The shared detection dataset for the cve-detect lesson.
function detectEvents() {
  const r = random(44);
  const events = [];
  const apps = ['app01', 'app02', 'app03'];
  // Normal egress: app servers talk to the database and the update server.
  for (let i = 0; i < 200; i++) events.push(fwEvent(at(8) + r.int(0, 10 * 3600) * 1000, { src_host: r.pick(apps), dest_ip: r.pick(['10.0.3.15', '10.0.3.15', '203.0.113.11']), dest_port: r.pick([1433, 1433, 443]) }));
  // A scanner probing the internet facing portal, caught by the IDS but harmless.
  for (let i = 0; i < 12; i++) events.push(idsEvent(at(r.int(0, 23), r.int(0, 59)), { signature: 'Suspicious web scanner activity', cve: '-', src_ip: '198.51.100.30', dest_host: 'portal01', action: 'detected' }));
  // Exploit attempts against a known issue, blocked at the perimeter.
  for (let i = 0; i < 8; i++) events.push(idsEvent(at(11, r.int(0, 59), r.int(0, 59)), { signature: 'Apache Log4j2 JNDI lookup in HTTP header', cve: 'CVE-2021-44228', src_ip: r.pick(['192.0.2.14', '203.0.113.150']), dest_host: r.pick(apps), action: 'blocked' }));
  // One attempt got through and the server made an outbound callback it never makes normally.
  events.push(idsEvent(at(15, 41, 2), { signature: 'Apache Log4j2 JNDI lookup in HTTP header', cve: 'CVE-2021-44228', src_ip: '198.51.100.250', dest_host: 'app03', action: 'detected' }));
  events.push(fwEvent(at(15, 41, 7), { src_host: 'app03', dest_ip: '198.51.100.250', dest_port: 1389, action: 'allowed' }));
  return events;
}

function lessonSiem(start, examples = []) {
  return { type: 'siem', events: detectEvents(), start, examples };
}

export default {
  id: 'cve',
  title: 'CVE case studies',
  short: 'CVEs',
  summary: 'Understand how vulnerabilities are named and scored, how to prioritise patching, and how famous flaws were detected and fixed, all from the defender\'s point of view.',
  intro: 'A handful of vulnerabilities cause a huge share of real incidents. This topic explains how flaws are catalogued and scored, how to decide what to fix first, and walks through several landmark vulnerabilities: what went wrong in plain terms, the timeline, the impact, how defenders spotted it, and how it was fixed. There is no exploit code here. The skill is reading advisories, prioritising, and recognising exploitation in your own evidence.',
  outcomes: [
    'Read a CVE identifier, a CVSS score and an advisory',
    'Use the KEV catalogue and exposure to prioritise patching',
    'Explain, in plain terms, what several landmark vulnerabilities allowed',
    'Recognise exploitation of a known flaw in logs and alerts',
    'Scope which systems were affected and which actually called out',
    'Choose the right short term and long term fixes'
  ],
  lessons: [
    {
      id: 'cve-basics',
      title: 'How vulnerabilities are catalogued',
      summary: 'CVE identifiers, CVSS and EPSS scores, the KEV catalogue, and where advisories come from.',
      minutes: 12,
      terms: [
        ['CVE', 'Common Vulnerabilities and Exposures. A public catalogue that gives each known flaw a unique identifier, like CVE-2021-44228, so everyone can refer to the same thing.'],
        ['CVSS', 'Common Vulnerability Scoring System. A score from 0 to 10 describing how severe a flaw is in the abstract. 9.0 and above is called critical.'],
        ['EPSS', 'Exploit Prediction Scoring System. An estimate of how likely a flaw is to be exploited in the near future, which CVSS does not tell you.'],
        ['KEV', 'CISA\'s Known Exploited Vulnerabilities catalogue: a list of flaws that are being exploited in the real world right now. If a flaw is on it, attackers are already using it.'],
        ['advisory', 'A notice from a vendor or coordinator describing a flaw, the affected versions and the fix.']
      ],
      workspace: { type: 'tools', title: 'Tools', op: 'iocs' },
      blocks: [
        { type: 'text', body: 'When someone finds a flaw in widely used software, it gets a **CVE** identifier so the whole industry can talk about the same thing. The format is `CVE`, the year, and a number: `CVE-2021-44228`. That is the one you will hear called **Log4Shell**. The name is just a label; the detail lives in advisories.' },
        { type: 'text', body: 'Each flaw usually gets a **CVSS** score from 0 to 10. It captures things like whether an attack can be done over the network, whether it needs a logged in user, and what it leads to. It is useful, but it describes severity in the abstract. It does not tell you whether anyone is actually using the flaw, or whether you are even exposed to it.' },
        { type: 'table', head: ['CVSS range', 'Label'], rows: [['0.1 to 3.9', 'Low'], ['4.0 to 6.9', 'Medium'], ['7.0 to 8.9', 'High'], ['9.0 to 10.0', 'Critical']] },
        { type: 'text', body: 'Two things fill the gap CVSS leaves. **EPSS** estimates how likely a flaw is to be exploited soon. The **KEV** catalogue goes further: it lists flaws known to be exploited in the wild right now. A flaw on the KEV list is not a maybe. Attackers are using it.' },
        { type: 'quiz', question: 'Flaw A has CVSS 9.8 but is not on the KEV list and has a very low EPSS score. Flaw B has CVSS 7.5, is on the KEV list, and affects software you run on the internet. Which do you patch first?', options: [
          { text: 'Flaw B, because it is being exploited right now and you are exposed', correct: true, why: 'A high CVSS says a flaw could be bad. KEV says a flaw is being used today. Being actively exploited on an exposed system beats a higher theoretical score that nobody is using.' },
          { text: 'Flaw A, because 9.8 is higher than 7.5', why: 'CVSS alone ignores whether anyone is exploiting the flaw and whether you are even exposed.' },
          { text: 'Neither is urgent until a vendor says so', why: 'KEV membership is exactly that signal, and it already applies to flaw B.' }
        ] },
        { type: 'text', body: 'Advisories come from a few places, and it is worth knowing them. The **NVD** (National Vulnerability Database) holds the CVE record and the CVSS score. **CISA** publishes the KEV catalogue and alerts. The **vendor** publishes the fix and the affected versions. For anything you are acting on, read the vendor advisory for the version detail.' },
        { type: 'table', head: ['Source', 'What you get there'], rows: [['NVD', 'The CVE record, description and CVSS score'], ['CISA KEV', 'Whether it is being exploited, and a due date for federal agencies'], ['Vendor advisory', 'Exact affected versions and the fix or workaround'], ['EPSS', 'The probability of exploitation in the next 30 days']] },
        { type: 'note', title: 'Links', body: `Every CVE has a page on the NVD, for example ${nvd('CVE-2021-44228')}. The ${KEV_LINK} is a single downloadable list, which is why it is easy to check your own systems against it, as the next lesson does.` }
      ]
    },
    {
      id: 'cve-prioritise',
      title: 'Deciding what to fix first',
      summary: 'Using exposure and the KEV catalogue to turn a long scan report into a short, ordered list.',
      minutes: 13,
      terms: [
        ['vulnerability scan', 'An automated check of your systems that lists the known flaws it finds, usually by CVE, with a severity.'],
        ['internet facing', 'Reachable from the internet. Flaws on these systems are far more urgent, because anyone can try them.'],
        ['attack surface', 'Everything an attacker could reach and try. Smaller is safer.'],
        ['patch window', 'A planned time to apply updates. Emergencies sometimes have to skip the queue.'],
        ['compensating control', 'A temporary measure that reduces risk when you cannot patch immediately, such as a firewall rule or a WAF signature.']
      ],
      workspace: { type: 'shell', cwd: '/home/learner', hostname: 'patching', motd: 'Scan export: scan.csv. KEV extract: kev.csv.\n', files: {
        '/home/learner/scan.csv': scanCsv(700, { plants: [
          ['vpn01', '203.0.113.10', 'yes', 'CVE-2023-4966', '9.4'],
          ['exch01', '203.0.113.12', 'yes', 'CVE-2021-26855', '9.8'],
          ['app05', '10.0.3.22', 'no', 'CVE-2021-44228', '10.0'],
          ['ad01', '10.0.1.10', 'no', 'CVE-2020-1472', '10.0'],
          ['web02', '203.0.113.14', 'yes', 'CVE-2026-31004', '9.9']
        ] }),
        '/home/learner/kev.csv': kevCsv(),
        '/home/learner/README.txt': 'scan.csv columns: host, ip, internet_facing, cve, cvss.\nkev.csv is this week\'s Known Exploited Vulnerabilities list.\n'
      } },
      blocks: [
        { type: 'text', body: 'A vulnerability scan of a mid sized company returns thousands of findings. You cannot patch them all at once, and treating them in CVSS order means spending the first week on critical flaws that nobody is exploiting on systems nobody can reach. A better order comes from three questions: is it being exploited, can an attacker reach it, and how bad is it if they do.' },
        { type: 'text', body: 'The strongest signal is the **KEV** catalogue crossed with **exposure**. A flaw that is on KEV and sits on an internet facing system is the definition of urgent. You have both files here: the scan and this week\'s KEV list.' },
        { type: 'example', title: 'Crossing the scan with KEV', steps: [
          { cmd: 'head -n 3 scan.csv', note: 'Remind yourself of the columns.' },
          { cmd: 'cut -d, -f1 kev.csv | tail -n +2 > kev-ids.txt', note: 'Just the KEV identifiers, without the header.' },
          { cmd: 'grep -f kev-ids.txt scan.csv', note: 'Every scan finding whose CVE is on the KEV list.' },
          { cmd: 'grep -f kev-ids.txt scan.csv | grep ",yes,"', note: 'Of those, the ones that are internet facing. This is your first list.' }
        ] },
        { type: 'task', text: 'Find the KEV findings on internet facing hosts.', hint: 'Extract the KEV ids, then `grep -f` the scan, then keep the `,yes,` rows.', check: (log) => log.some((e) => e.type === 'command' && e.name === 'grep' && /yes/.test(e.args.join(' '))) },
        { type: 'text', body: 'Two findings come back: the VPN with a Citrix flaw and the Exchange server with ProxyLogon. Both are on KEV and both face the internet. The Log4j and Netlogon findings are also on KEV and also serious, but they are internal, so they come next, not first. The 9.9 on web02 is scary by score but it is a 2026 identifier that is not on KEV, so it does not jump the queue on its own.' },
        { type: 'quiz', question: 'Your scan has 3,000 findings. 40 are KEV matches. 6 of those are internet facing. How should you spend the first day?', options: [
          { text: 'On the 6 internet facing KEV findings', correct: true, why: 'Exploited plus reachable is the smallest, most urgent list. The other 34 KEV findings are next, then the rest by exposure and severity.' },
          { text: 'On every finding with CVSS 9.0 or higher', correct: false, why: 'That could be hundreds of findings, most of them not exploited and many unreachable. You would spend the day on lower risk than the 6.' },
          { text: 'In the order the scanner printed them', why: 'Scanners print in no particular risk order. You have to impose one.' }
        ] },
        { type: 'text', body: 'When you cannot patch something straight away, for example because the fix needs testing or downtime, you reduce the risk in the meantime with a **compensating control**: a firewall rule that blocks access to the service, a WAF signature that blocks the known exploit pattern, or taking the system offline if it is not essential. The next lessons show real examples.' },
        { type: 'answer', question: 'Reducing your attack surface is one of the cheapest defences. What should you do with an internet facing service that nobody actually needs reachable from outside?', accept: ['restrict it', 'take it off the internet', 'firewall it', 'block it', 'make it internal', 'remove it', 'take it offline', 'put it behind a vpn'], hint: 'If it does not need to be reachable from the internet, it should not be.', explain: 'A service that is not exposed cannot be attacked from outside, no matter how many flaws it has. Removing needless exposure often fixes more risk than a month of patching.' },
        { type: 'note', title: 'Patch, but also prepare', body: 'Prioritised patching reduces risk, but it never reaches zero, because fixes take time and new flaws appear constantly. That is why the detection and response skills in the other topics matter: you assume some exploitation will succeed and make sure you can see it.' }
      ]
    },
    {
      id: 'cve-detect',
      title: 'Seeing a known flaw being used',
      summary: 'How exploitation of a catalogued vulnerability shows up in alerts, logs and network behaviour.',
      minutes: 13,
      terms: [
        ['IDS', 'Intrusion detection system. Watches network traffic (or a host) and raises an alert when it matches a signature, such as a known exploit pattern.'],
        ['signature', 'A rule that describes a known attack so the IDS can flag it. Named for the flaw or technique it detects.'],
        ['egress', 'Traffic leaving your network. A server reaching out to a new external address, especially straight after an exploit attempt, is a strong signal.'],
        ['callback', 'A connection an exploited system makes back to the attacker to fetch a payload or take instructions. Often the first sign that an attempt succeeded.']
      ],
      workspace: lessonSiem('index=ids', ['index=ids | stats count by signature, action', 'index=ids action=detected cve=CVE-2021-44228 | table _time, src_ip, dest_host', 'index=firewall dest_port=1389', 'index=firewall dest_port=1389 action=allowed | table _time, src_host, dest_ip']),
      blocks: [
        { type: 'text', body: 'A patch stops a flaw being exploited. Detection tells you whether anyone tried before you patched, and whether they succeeded. For a catalogued vulnerability, exploitation usually leaves three kinds of trace: an alert from a signature, unusual behaviour on the target, and a connection back out to the attacker.' },
        { type: 'text', body: 'An **IDS** compares traffic against **signatures**. When a well known flaw is published, detection vendors release signatures for it within hours, so attempts to use it get flagged. The dataset on the right mixes ordinary scanning with attempts against a Log4j flaw.' },
        { type: 'task', text: 'Count the IDS signatures by name and action to see what fired.', hint: '`index=ids | stats count by signature, action`', check: (log) => queried(log, (q) => q.includes('index=ids') && q.includes('stats')) },
        { type: 'text', body: 'Most of the Log4j attempts show `action=blocked`: the perimeter stopped them. One shows `action=detected` against `app03` and was not blocked. An alert that something was attempted is useful, but the question that matters is always the next one: did it work?' },
        { type: 'text', body: 'The best answer is often in your **egress**. A flaw like Log4Shell works by making the target connect back out to a server the attacker controls, a **callback**. Application servers have a small, predictable set of places they talk to. A new outbound connection, right after an exploit attempt, is a strong sign the attempt succeeded.' },
        { type: 'task', text: 'Look at the firewall for outbound connections to port 1389, the port the callback used, and see which were allowed.', hint: '`index=firewall dest_port=1389 action=allowed`', check: (log) => queried(log, (q) => q.includes('index=firewall') && q.includes('1389')) },
        { type: 'quiz', question: 'The IDS blocked most attempts but `app03` both was attempted and then made an allowed outbound connection to the attacker\'s address on an unusual port. What does that tell you?', options: [
          { text: 'app03 probably executed the attacker\'s code and should be treated as compromised', correct: true, why: 'The attempt was not blocked and the server then called out to the attacker, which it never does normally. That is the sequence of a successful exploit, so app03 moves from "attempted" to "contain and investigate".' },
          { text: 'Nothing. The IDS blocked the other attempts, so all are handled', why: 'The other attempts were blocked, but this one was not, and the callback suggests it succeeded.' },
          { text: 'The firewall is misconfigured', why: 'The firewall allowing the egress is part of the problem, but the event itself is evidence of a successful attack, not just a config error.' }
        ] },
        { type: 'order', question: 'Put these detection steps in order when a signature fires for a known flaw.', items: ['Confirm the alert is real and which host was targeted', 'Check whether the attempt was blocked or got through', 'Look for a callback or other unusual behaviour from the target', 'If it succeeded, contain the host and start an investigation', 'Make sure the flaw is patched or blocked everywhere else'], explain: 'Signatures tell you something was attempted. Behaviour on the target tells you whether it worked. The last step turns one incident into prevention across the fleet.' },
        { type: 'note', title: 'Egress control is detection and prevention', body: 'If app03 had been unable to make that outbound connection, the attack would have failed even though the server was vulnerable. Limiting where servers may connect out to is one of the most effective controls against this whole class of flaw.' }
      ]
    },
    {
      id: 'cve-log4shell',
      title: 'Case study: Log4Shell',
      summary: 'A logging library flaw that put much of the internet at risk overnight, and how defenders responded.',
      minutes: 12,
      terms: [
        ['Log4j', 'A hugely popular Java logging library. Because so much software includes it, a flaw in it affected an enormous number of systems at once.'],
        ['remote code execution', 'The most serious outcome: an attacker runs their own code on your system. Usually abbreviated RCE.'],
        ['software supply chain', 'The web of third party components your software is built from. A flaw in one shared component affects everything that includes it.'],
        ['software bill of materials', 'An SBOM: a list of the components inside a piece of software. It lets you answer "do we use the flawed thing?" quickly.']
      ],
      workspace: { type: 'tools', title: 'Tools', op: 'iocs' },
      blocks: [
        { type: 'text', body: 'In December 2021 a flaw was published in **Log4j**, a Java logging library included in a staggering amount of software, from web applications to network devices to games. The flaw, **CVE-2021-44228**, meant that if an attacker could get a crafted piece of text logged, which is often as easy as putting it in a username or a header, the vulnerable system could be made to fetch and run code the attacker chose. That is **remote code execution**, the worst case, and it needed no login.' },
        { type: 'timeline', items: [
          ['9 Dec 2021', 'The flaw is disclosed publicly, with exploitation already happening in the wild.'],
          ['10 Dec 2021', 'Mass scanning of the whole internet begins. Defenders race to find where they use Log4j.'],
          ['10 to 17 Dec 2021', 'Apache releases several updates as earlier fixes are found to be incomplete. CISA adds it to KEV and orders federal agencies to patch.'],
          ['Weeks after', 'Vendors ship patched versions of thousands of products that bundle Log4j. Finding every copy is the hard part.']
        ] },
        { type: 'text', body: 'The reason it was so serious was the **software supply chain**. Almost nobody installs Log4j directly. It arrives bundled inside other software, often several layers deep, so the first and hardest question was simply: where do we even have it? Organisations that kept a **software bill of materials** could answer in minutes. Everyone else spent days searching.' },
        { type: 'quiz', question: 'Why was "just patch Log4j" so much harder than it sounds?', options: [
          { text: 'Log4j was bundled inside countless other products, so you had to find every copy first', correct: true, why: 'A single application can contain Log4j several times over through its dependencies, and so can appliances and devices you cannot easily patch. Knowing where it was, was most of the work.' },
          { text: 'The patch did not work', why: 'The first fix was incomplete and needed follow ups, but the real difficulty was finding every affected system.' },
          { text: 'Log4j is written in a rare language', why: 'Java is one of the most common languages. Its ubiquity was the problem, not its rarity.' }
        ] },
        { type: 'text', body: 'Defenders responded on several fronts at once. They deployed IDS and WAF signatures to detect and block the attack pattern. They hunted for the callbacks that marked successful exploitation, exactly as the previous lesson did. They cut off outbound connections from servers that had no reason to make them, which broke the attack even on unpatched systems. And they worked through their estate finding and updating every copy of the library.' },
        { type: 'order', question: 'Put a sensible Log4Shell response in order for a team that has just heard about it.', items: ['Find out where you use Log4j, including inside bundled software', 'Block the exploit pattern at the WAF and IDS and restrict outbound connections from servers', 'Hunt for callbacks and other signs of successful exploitation', 'Patch to a fixed version everywhere, prioritising internet facing systems', 'Keep watching, because new affected products keep being found'], explain: 'The temporary blocks buy time while you find and patch everything. Hunting for callbacks catches anyone who got in before the blocks went up.' },
        { type: 'note', title: 'What it changed', body: `Log4Shell pushed software bills of materials and supply chain visibility from nice to have to expected. The ${nvd('CVE-2021-44228')} record and the vendor advisories remain the reference for affected versions.` }
      ]
    },
    {
      id: 'cve-wannacry',
      title: 'Case study: EternalBlue and WannaCry',
      summary: 'A wormable Windows flaw, the ransomware that spread with it, and why a patch existed before the outbreak.',
      minutes: 12,
      terms: [
        ['SMBv1', 'An old version of the Windows file sharing protocol. The flaw known as EternalBlue was in it. It should be disabled everywhere.'],
        ['wormable', 'A flaw that lets malware spread by itself from machine to machine with no human action. These cause the fastest, widest outbreaks.'],
        ['ransomware', 'Malware that encrypts files and demands payment for the key.'],
        ['lateral movement', 'An attacker spreading from the first machine they control to others inside the same network.']
      ],
      workspace: { type: 'tools', title: 'Tools', op: 'cidr' },
      blocks: [
        { type: 'text', body: 'In May 2017 the **WannaCry** ransomware spread across the world in a day, hitting hospitals, factories and transport systems. What made it so fast was that it did not need anyone to click anything. It used **EternalBlue**, a flaw in the old **SMBv1** file sharing protocol (**CVE-2017-0144**), to copy itself from one vulnerable Windows machine to the next automatically. A flaw that spreads by itself like this is called **wormable**, and it is the most dangerous kind.' },
        { type: 'timeline', items: [
          ['14 Mar 2017', 'Microsoft releases a patch for the SMBv1 flaw, two months before the outbreak.'],
          ['12 May 2017', 'WannaCry begins spreading, encrypting files and demanding ransom, moving between machines on its own.'],
          ['12 May 2017', 'A researcher registers a domain the malware checks, which slows the spread.'],
          ['After', 'Microsoft takes the unusual step of patching long unsupported Windows versions. SMBv1 is disabled by default in later releases.']
        ] },
        { type: 'text', body: 'The painful lesson is in the first line of that timeline. The patch existed two months before the outbreak. The organisations hit hardest were running old, unpatched systems, often because the machines ran equipment that was hard to update or was thought too important to take offline. The flaw was critical and wormable, and still many systems went unpatched until it was too late.' },
        { type: 'quiz', question: 'A patch for EternalBlue was available two months before WannaCry. Why did so many organisations still get hit?', options: [
          { text: 'Unpatched and unsupported systems, and SMBv1 left enabled and reachable', correct: true, why: 'Old machines, hard to patch equipment, and the legacy SMBv1 protocol being on and reachable across flat networks let the worm spread. The fix existed; it had not been applied.' },
          { text: 'The patch made systems slower, so people removed it', why: 'That was not the cause. The systems were simply never patched.' },
          { text: 'There was no way to detect it', why: 'Detection was possible, but prevention, patching and disabling SMBv1, would have stopped it entirely.' }
        ] },
        { type: 'text', body: 'From the defender\'s side, a worm like this has a very visible shape on the network. One infected machine suddenly tries to connect to many others on the file sharing port, **445**, fanning out across the network. Spotting that one host talking to dozens of others on 445, and segmenting networks so it cannot, are the core defences, alongside patching and turning SMBv1 off.' },
        { type: 'order', question: 'Put these defences against a wormable SMB flaw in order of how fundamental they are.', items: ['Disable SMBv1 entirely', 'Patch the flaw', 'Block file sharing ports between network segments so a worm cannot fan out', 'Alert when one host connects to many others on port 445'], explain: 'Removing the old protocol and patching stop the flaw existing. Segmentation limits how far any worm can spread. Detection catches what the first three miss.' },
        { type: 'note', title: 'Still relevant', body: `EternalBlue based malware is still seen years later, because unpatched systems persist. SMBv1 should be off everywhere. The ${nvd('CVE-2017-0144')} record and Microsoft\'s advisory give the affected versions.` }
      ]
    },
    {
      id: 'cve-respond',
      title: 'Responding to a new critical flaw',
      summary: 'What to do in the first hours when a serious vulnerability in software you run is announced.',
      minutes: 11,
      terms: [
        ['virtual patch', 'A rule on a WAF, IDS or firewall that blocks exploitation of a flaw without changing the vulnerable software itself. A fast stopgap.'],
        ['emergency change', 'A patch applied outside the normal schedule because the risk of waiting is too high.'],
        ['threat hunt', 'Actively searching your own data for signs that a flaw was already exploited, rather than waiting for an alert.'],
        ['retrospective search', 'Searching old logs for an indicator you only learned about today, to find exploitation that happened before you knew.']
      ],
      workspace: lessonSiem('index=ids', ['index=ids cve=CVE-2021-44228 | stats earliest(_time) as first, latest(_time) as last, count', 'index=ids cve=CVE-2021-44228 action=detected | table _time, src_ip, dest_host']),
      blocks: [
        { type: 'text', body: 'A critical vulnerability in software you run has just been announced, and it is on KEV. The first hours matter. The goal is to reduce the risk now, find out if you were already hit, and fix it properly, in that order, because a proper fix often takes longer than you can safely wait.' },
        { type: 'table', head: ['Step', 'Why it comes when it does'], rows: [['Confirm you are affected', 'Which products and versions? An SBOM or asset inventory answers fastest'], ['Reduce risk now', 'A virtual patch or firewall rule buys time while you prepare the real fix'], ['Hunt retrospectively', 'The flaw may have been used before today. Search old logs for the indicators'], ['Patch properly', 'As an emergency change, internet facing systems first'], ['Verify and watch', 'Confirm the fix, and keep detection on in case of missed systems']] },
        { type: 'text', body: 'A **virtual patch** is the key idea for the "reduce risk now" step. You cannot always deploy a software update in an hour, but you can often block the exploitation pattern at a WAF or IDS, or cut off the network access the flaw needs, in minutes. It is not a substitute for patching, but it changes the clock from minutes to days.' },
        { type: 'text', body: 'Just as important is the **retrospective search**. When you learn an indicator today, such as an IP address or a signature, the flaw may have been used against you days or weeks ago. Searching your historical logs for it is how you find exploitation that happened before anyone had a signature for it.' },
        { type: 'task', text: 'You just learned this flaw is being exploited. Search your IDS history for when attempts against it first appeared.', hint: '`index=ids cve=CVE-2021-44228 | stats earliest(_time) as first, latest(_time) as last, count`', check: (log) => queried(log, (q) => q.includes('earliest') && q.includes('cve')) },
        { type: 'quiz', question: 'You patch the internet facing systems within hours. Why is the job not finished?', options: [
          { text: 'You still need to hunt for exploitation that happened before you patched, and patch everything else', correct: true, why: 'Patching stops future exploitation. It does nothing about an attacker who got in yesterday, and internal and bundled copies of the software still need fixing. Containment of any successful attack is a separate task.' },
          { text: 'It is finished, because the exposed systems are patched', why: 'A patch is not a time machine. Anyone who exploited the flaw before the patch is still there.' },
          { text: 'You only need to wait for the vendor to confirm', why: 'The vendor cannot tell you whether you were already compromised. Only your own hunt can.' }
        ] },
        { type: 'note', title: 'Communication is part of response', body: 'Keep a running record and tell the people who need to know: what is affected, what you have done, and what is still open. A clear timeline written as you go is what the final report and any regulatory notification are built from.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'cve-kev-exposed',
      title: 'Patch this one first',
      difficulty: 'easy',
      points: 100,
      skills: ['KEV', 'grep -f', 'prioritisation'],
      prepare: ['cve-prioritise'],
      brief: 'Your weekly scan found over a thousand vulnerabilities across the estate, and you have time to emergency patch exactly one system today. The rule is simple: a flaw that is being actively exploited, on a system anyone on the internet can reach, comes first.',
      goal: 'Cross reference the scan against this week\'s KEV list and find the one internet facing host with a known exploited vulnerability. Submit its name as `HW{host}`.',
      flag: 'qZd4HUQuyFjQ0V1e',
      workspace: () => ({
        type: 'shell',
        cwd: '/home/learner',
        hostname: 'patching',
        motd: 'scan.csv and kev.csv are in your home folder.\n',
        files: {
          '/home/learner/scan.csv': scanCsv(4242, { count: 60, plants: [
            ['svc-db09', '10.0.3.19', 'no', 'CVE-2020-1472', '10.0'],
            ['build02', '10.0.6.40', 'no', 'CVE-2021-44228', '10.0'],
            ['portal03', '203.0.113.33', 'yes', 'CVE-2023-4966', '9.4'],
            ['web07', '203.0.113.41', 'yes', 'CVE-2026-44120', '9.8'],
            ['mail04', '203.0.113.52', 'yes', 'CVE-2026-20771', '8.8']
          ] }),
          '/home/learner/kev.csv': kevCsv(),
          '/home/learner/README.txt': 'scan.csv: host, ip, internet_facing, cve, cvss.\nkev.csv: this week\'s Known Exploited Vulnerabilities.\n'
        }
      }),
      hints: ['A high CVSS alone does not make something a KEV finding. Start from the KEV list.', 'Extract the KEV identifiers, search the scan for them, then keep only the internet facing rows.', '`cut -d, -f1 kev.csv | tail -n +2 > ids.txt`, then `grep -f ids.txt scan.csv | grep ",yes,"`.'],
      writeup: {
        how: 'Pulling the identifiers out of kev.csv and running `grep -f` against the scan returns the findings that are actively exploited. Keeping only the `,yes,` rows leaves one: `portal03`, internet facing, with CVE-2023-4966 (the Citrix flaw known as CitrixBleed). The two internal hosts with Log4j and Netlogon are also on KEV but are not reachable from outside, so they come next. web07 has a higher CVSS (9.8) but its identifier is a 2026 CVE that is not on the KEV list, so it does not jump the queue.',
        why: 'The combination of actively exploited and internet reachable is the shortest, sharpest list a vulnerability programme produces. Sorting by CVSS alone would have put web07 first, on a flaw nobody is using, while leaving the one attackers are actually exploiting for later.',
        fix: 'Emergency patch portal03, and because CitrixBleed can expose session tokens, invalidate active sessions as well. Then work through the internal KEV findings, and reduce exposure by checking whether mail04 and web07 need to face the internet at all.'
      }
    },
    {
      id: 'cve-top-product',
      title: 'Where it hurts most',
      difficulty: 'easy',
      points: 100,
      skills: ['KEV', 'counting', 'pipes'],
      prepare: ['cve-prioritise', 'cve-basics'],
      brief: 'Leadership wants a single number for the board: which known exploited vulnerability affects the most of our systems, so the patching effort can be named and tracked. You have the scan and the KEV list.',
      goal: 'Find the KEV vulnerability that appears on the most hosts in the scan and submit it as `HW{CVE-id}`.',
      flag: 'daB5WAaA526SzyOfAotZ0HF/',
      workspace: () => {
        const plants = [];
        for (const host of ['app01', 'app02', 'app03', 'app04', 'app05', 'web01', 'wiki02']) plants.push([host, `10.0.4.${plants.length + 10}`, 'no', 'CVE-2021-44228', '10.0']);
        for (const host of ['dc01', 'dc02']) plants.push([host, `10.0.1.${plants.length}`, 'no', 'CVE-2020-1472', '10.0']);
        plants.push(['mft01', '203.0.113.60', 'yes', 'CVE-2023-34362', '9.8']);
        plants.push(['legacy01', '203.0.113.61', 'yes', 'CVE-2014-6271', '9.8']);
        return {
          type: 'shell',
          cwd: '/home/learner',
          hostname: 'patching',
          motd: 'scan.csv and kev.csv are in your home folder.\n',
          files: {
            '/home/learner/scan.csv': scanCsv(9001, { count: 55, plants }),
            '/home/learner/kev.csv': kevCsv(),
            '/home/learner/README.txt': 'scan.csv: host, ip, internet_facing, cve, cvss. kev.csv: Known Exploited Vulnerabilities.\n'
          }
        };
      },
      hints: ['Only KEV vulnerabilities count here, so filter the scan to KEV findings first.', 'Then count how many distinct hosts each KEV CVE appears on. The classic counting pipeline does it.', '`cut -d, -f1 kev.csv | tail -n +2 > ids.txt; grep -f ids.txt scan.csv | cut -d, -f4 | sort | uniq -c | sort -rn | head`.'],
      writeup: {
        how: 'Filtering the scan to KEV findings and counting by CVE shows CVE-2021-44228 (Log4Shell) on seven hosts, CVE-2020-1472 on two, and the MOVEit and Shellshock flaws on one each. Log4Shell is the most widespread, which matches real life: because the library was bundled everywhere, it tends to show up on many systems at once.',
        why: 'Counting by vulnerability turns a flat list of findings into a named campaign the organisation can plan and measure, "remove Log4Shell from all seven hosts", rather than seven unrelated tickets. Widespread flaws are also where automation and a software bill of materials pay off most.',
        fix: 'Track the Log4j remediation as one effort to completion, and use the exercise to start building an inventory of which systems contain which components, so the next widespread flaw can be answered in minutes.'
      }
    },
    {
      id: 'cve-callback',
      title: 'Which one answered',
      difficulty: 'medium',
      points: 150,
      skills: ['IDS', 'egress', 'scoping'],
      prepare: ['cve-detect', 'cve-log4shell'],
      brief: 'A Log4j exploit attempt signature fired against several of your application servers this afternoon. Most attempts were blocked at the perimeter, but you need to know whether any server actually ran the attacker\'s code. These servers normally only talk to the database and the update server, so an outbound connection anywhere else is a red flag.',
      goal: 'Find the one application server that made an outbound connection to the attacker after the exploit attempt, and submit its name as `HW{host}`.',
      flag: '9vfW4dz1yOUN',
      workspace: () => {
        const r = random(1389);
        const events = [];
        const apps = ['app01', 'app02', 'app03', 'app04', 'app05', 'app06'];
        const attackerIps = ['198.51.100.250', '203.0.113.88', '192.0.2.44'];
        // Normal egress for every app server: the database or the update server.
        for (let i = 0; i < 600; i++) {
          const toDb = r.next() < 0.75;
          events.push(fwEvent(at(8) + r.int(0, 10 * 3600) * 1000, { src_host: r.pick(apps), dest_ip: toDb ? '10.0.3.15' : '203.0.113.11', dest_port: toDb ? 1433 : 443 }));
        }
        // Exploit attempts across all servers; most blocked at the firewall.
        for (let i = 0; i < 50; i++) {
          const host = r.pick(apps);
          events.push(idsEvent(at(r.int(9, 17), r.int(0, 59), r.int(0, 59)), { signature: 'Apache Log4j2 JNDI lookup attempt', cve: 'CVE-2021-44228', src_ip: r.pick(attackerIps), dest_host: host, action: 'blocked' }));
        }
        // A handful of attempts the perimeter did not block.
        for (const host of ['app02', 'app05', 'app06']) events.push(idsEvent(at(14, r.int(0, 59), r.int(0, 59)), { signature: 'Apache Log4j2 JNDI lookup attempt', cve: 'CVE-2021-44228', src_ip: '198.51.100.250', dest_host: host, action: 'detected' }));
        // Only app06 then calls out to the attacker on the callback port.
        events.push(fwEvent(at(14, 52, 11), { src_host: 'app06', dest_ip: '198.51.100.250', dest_port: 1389, action: 'allowed' }));
        events.push(fwEvent(at(14, 52, 13), { src_host: 'app06', dest_ip: '198.51.100.250', dest_port: 8080, action: 'allowed' }));
        // A noisy monitoring agent on app01 that talks to an external metrics service, to rule out.
        for (let t = at(8); t < at(18); t += 1800000) events.push(fwEvent(t, { src_host: 'app01', dest_ip: '203.0.113.30', dest_port: 443 }));
        return { type: 'siem', events, start: 'index=ids cve=CVE-2021-44228' };
      },
      hints: ['An exploit attempt is not the same as a successful one. The attempts are in the ids index; whether it worked shows in the firewall.', 'These servers only ever connect out to the database (1433) and the update server (443). Look for an app server connecting anywhere else.', '`index=firewall action=allowed NOT dest_ip=10.0.3.15 NOT dest_port=443 | stats count by src_host, dest_ip, dest_port`, and match it against the servers that were attempted.'],
      writeup: {
        how: 'The ids index shows exploit attempts against several servers, most marked blocked and three (app02, app05, app06) marked detected, meaning they reached the server. The attempts alone do not say what succeeded. The firewall does: filtering outbound connections that are not to the database or the update server leaves app06 connecting to the attacker at 198.51.100.250 on ports 1389 and 8080, right after the attempt. app01 also has external egress, but it is the regular half hourly metrics connection to a known service, so it is ruled out.',
        why: 'For a flaw like Log4Shell, the callback is the dividing line between "someone tried" and "someone is in". IDS tells you about attempts; your own egress tells you about outcomes. Because the servers have a tiny set of normal destinations, the anomaly is obvious once you look at the right data.',
        fix: 'Treat app06 as compromised: isolate it and investigate what the callback fetched and what ran. Patch Log4j across all the servers, and restrict outbound connections so servers can only reach the few destinations they need, which would have stopped the callback and defeated the attack.'
      }
    },
    {
      id: 'cve-patient-zero',
      title: 'Spreading sideways',
      difficulty: 'medium',
      points: 200,
      skills: ['worms', 'SMB', 'fan-out'],
      prepare: ['cve-wannacry', 'cve-detect'],
      brief: 'A help desk ticket reports files being renamed and a ransom note on a finance workstation. Firewall logs for the finance network show a burst of connections on the file sharing port, 445, between internal machines. This looks like a worm spreading over SMB. You need the machine it started from, the one reaching out to everything else.',
      goal: 'Find the internal host that connected to the most other hosts on port 445 and submit it as `HW{host}`.',
      flag: 'nYORMFzXk4OybJ4xNw==',
      workspace: () => {
        const r = random(445);
        const events = [];
        const hosts = Array.from({ length: 40 }, (_, i) => `fin-ws-${String(i + 1).padStart(2, '0')}`);
        // Normal SMB: workstations talk to the two file servers only.
        for (let i = 0; i < 300; i++) events.push(fwEvent(at(8) + r.int(0, 9 * 3600) * 1000, { src_host: r.pick(hosts), dest_host: r.pick(['fin-file01', 'fin-file02']), dest_port: 445 }));
        // A backup server that legitimately touches many machines, on a different port.
        for (const host of hosts) events.push(fwEvent(at(2, r.int(0, 59)), { src_host: 'fin-backup01', dest_host: host, dest_port: 9443 }));
        // Patient zero: one workstation fanning out to dozens of others on 445.
        const zero = 'fin-ws-17';
        let t = at(13, 20);
        for (const host of hosts.filter((h) => h !== zero)) {
          t += r.int(1, 4) * 1000;
          events.push(fwEvent(t, { src_host: zero, dest_host: host, dest_port: 445, action: r.next() < 0.3 ? 'allowed' : 'allowed' }));
        }
        // Second generation: a couple of the infected machines start spreading too, but to fewer hosts.
        for (const second of ['fin-ws-04', 'fin-ws-28']) {
          for (const host of r.shuffle(hosts).slice(0, r.int(5, 9))) {
            events.push(fwEvent(at(13, 40 + r.int(0, 15), r.int(0, 59)), { src_host: second, dest_host: host, dest_port: 445 }));
          }
        }
        return { type: 'siem', events, start: 'index=firewall dest_port=445' };
      },
      hints: ['A worm spreading over SMB shows as one source connecting to many destinations on port 445. Count destinations per source.', 'Watch out for two distractions: the file servers everyone talks to normally, and the backup server, which touches many machines but on a different port.', '`index=firewall dest_port=445 | stats dc(dest_host) as targets by src_host | sort -targets | head`.'],
      writeup: {
        how: 'Counting distinct destinations per source on port 445 puts `fin-ws-17` far ahead: it connected to almost every other workstation in a few minutes, which no normal workstation does. Two machines it reached, fin-ws-04 and fin-ws-28, then start spreading too but to far fewer hosts, which is the second generation. The backup server also touches many machines, but on port 9443, so filtering to 445 removes it, and the file servers are destinations, not sources, of the fan out.',
        why: 'Self spreading malware has a distinctive network shape: a sudden one to many pattern on a spreading port, growing in generations. You can find patient zero from the network alone, by who reached out to the most machines first, without any host evidence. That tells responders which machine to examine for how the infection began.',
        fix: 'Isolate fin-ws-17 and the machines it reached, and rebuild rather than clean. To prevent recurrence: disable SMBv1, patch, and segment the network and restrict workstation to workstation SMB so a worm cannot fan out like this.'
      }
    },
    {
      id: 'cve-identify',
      title: 'Name the vulnerability',
      difficulty: 'medium',
      points: 200,
      skills: ['advisories', 'KEV', 'cross-referencing'],
      prepare: ['cve-basics', 'cve-detect'],
      brief: 'An incident writeup from another team describes what they saw but never names the CVE, which makes it hard to check your own systems. They describe a flaw in a specific product, being actively exploited, with a recognisable behaviour. Your job is to match their description to the right CVE so you can look up whether you are affected.',
      goal: 'Read the incident notes and the KEV extract, identify the vulnerability being described, and submit its identifier as `HW{CVE-id}`.',
      flag: 'KIYNBwUl0M2I6tP6p3F2g7nZ',
      workspace: () => ({
        type: 'shell',
        cwd: '/home/learner',
        hostname: 'analyst',
        motd: 'incident-notes.txt and kev.csv are in your home folder.\n',
        files: {
          '/home/learner/incident-notes.txt': [
            'Incident 2026-0147, shared by the regional SOC.',
            '',
            'Affected product: Progress MOVEit Transfer (managed file transfer, internet facing).',
            'Status: actively exploited in the wild, mass campaign against many organisations.',
            'Observed behaviour:',
            '  - Attackers reached the web interface with no valid account.',
            '  - A web shell appeared under the application\'s own folders.',
            '  - Large numbers of stored files were downloaded over a short window.',
            'Root cause (vendor advisory): a flaw in the web application allowed access to the database',
            'behind it without authentication.',
            '',
            'We did not record the CVE identifier. Please map this to the right one from the KEV list',
            'so each site can check its own MOVEit deployment and patch level.'
          ].join('\n') + '\n',
          '/home/learner/kev.csv': kevCsv(),
          '/home/learner/README.txt': 'kev.csv columns: cveID, vendorProject, product.\n'
        }
      }),
      hints: ['The notes name the vendor and product clearly. The KEV list has a column for each.', 'Search the KEV list for the product mentioned in the notes.', '`grep -i moveit kev.csv` gives the vendor, product and the CVE identifier.'],
      writeup: {
        how: 'The incident notes name the product directly: Progress MOVEit Transfer, being mass exploited, with unauthenticated access leading to data theft. Searching the KEV extract with `grep -i moveit kev.csv` returns one row, CVE-2023-34362. With the identifier in hand, each site can look it up on the NVD and the vendor advisory and check its own version against the fixed one.',
        why: 'Incident reports and threat intelligence often describe behaviour without a clean identifier. Being able to map a description to a CVE, using the vendor and product names, is what lets you turn someone else\'s incident into an action on your own estate: are we running this product, at a vulnerable version, and exposed?',
        fix: 'Check every MOVEit deployment against the fixed version, apply the vendor patch, and because this flaw was used for data theft, hunt for the web shell and unusual bulk downloads in your own logs rather than assuming patching is enough.'
      }
    },
    {
      id: 'cve-first-seen',
      title: 'Before we knew',
      difficulty: 'medium',
      points: 200,
      skills: ['retrospective search', 'timelines', 'exposure window'],
      prepare: ['cve-respond'],
      brief: 'A flaw in your internet facing portal was disclosed and you deployed an IDS signature for it the moment one was available, at 12:00 UTC on 13 March. The signature has been firing since. The worrying question is whether attackers were using the flaw against you before you had any way to see it. Your IDS was recording full traffic the whole time, so the early attempts are in the data even though nothing alerted on them at the time.',
      goal: 'Search the IDS history for the earliest attempt against this flaw and submit the time of the first one in UTC, as `HW{HH:MM:SS}`.',
      flag: 'x0YmdTdJelMfrfIz',
      workspace: () => {
        const r = random(26855);
        const events = [];
        const cve = 'CVE-2021-26855';
        const ips = ['203.0.113.50', '198.51.100.9', '192.0.2.120', '203.0.113.201'];
        // Ordinary unrelated alerts across the day, to add noise.
        for (let i = 0; i < 120; i++) events.push(idsEvent(at(r.int(0, 23), r.int(0, 59), r.int(0, 59)), { signature: r.pick(['Generic web scanner', 'Outdated TLS version offered', 'Directory listing attempt']), cve: '-', src_ip: `192.0.2.${r.int(2, 200)}`, dest_host: 'portal01', severity: 'low', action: 'detected' }));
        // The first probe for this flaw, well before the signature existed.
        events.push(idsEvent(at(5, 3, 17), { signature: 'Exchange SSRF access to internal endpoint', cve, src_ip: '203.0.113.50', dest_host: 'portal01', action: 'detected' }));
        // A few more early attempts during the morning.
        for (const [h, m, s] of [[6, 41, 9], [8, 2, 55], [9, 30, 12], [11, 15, 44]]) events.push(idsEvent(at(h, m, s), { signature: 'Exchange SSRF access to internal endpoint', cve, src_ip: r.pick(ips), dest_host: 'portal01', action: 'detected' }));
        // Many attempts after the signature went live at 12:00.
        for (let i = 0; i < 40; i++) events.push(idsEvent(at(r.int(12, 23), r.int(0, 59), r.int(0, 59)), { signature: 'Exchange SSRF access to internal endpoint', cve, src_ip: r.pick(ips), dest_host: 'portal01', action: 'detected' }));
        return { type: 'siem', events, start: `index=ids cve=${cve}` };
      },
      hints: ['Filter to just this flaw, then find the earliest event rather than scrolling.', '`stats earliest(_time)` gives the first time something was seen.', '`index=ids cve=CVE-2021-26855 | stats earliest(_time) as first` and read the time in UTC.'],
      writeup: {
        how: 'Filtering the ids index to the flaw and taking `earliest(_time)` returns the first attempt at 05:03:17 UTC, nearly seven hours before the signature was deployed at 12:00. Those early attempts were recorded but raised no alert at the time, because there was no rule for them yet. Only a retrospective search over the stored data finds them.',
        why: 'The gap between when a flaw is first used against you and when you can detect it is the exposure window, and it is almost always wider than people assume. When a new indicator or signature arrives, searching history for it is how you discover exploitation that already happened. Here it changes the conclusion from "we blocked it from the start" to "we were probed hours earlier and need to check whether any of those early attempts succeeded".',
        fix: 'Investigate the early attempts for signs of success, not just the ones after noon. Keep enough log and traffic history to make retrospective searches possible, and treat the first seen time as the real start of the exposure window when scoping the incident.'
      }
    },
    {
      id: 'cve-double-exposed',
      title: 'Vulnerable and under fire',
      difficulty: 'hard',
      points: 300,
      skills: ['correlation', 'KEV', 'IDS', 'prioritisation'],
      prepare: ['cve-prioritise', 'cve-detect'],
      brief: 'You have three pieces of evidence: this week\'s scan, the KEV list, and today\'s IDS alerts. Plenty of systems are vulnerable, and plenty are being probed, but those are mostly different systems. The one that cannot wait is the system that is both: carrying a known exploited vulnerability, reachable from the internet, and being actively attacked right now.',
      goal: 'Find the host that is internet facing, has a KEV vulnerability in the scan, and is the target of IDS alerts for that same vulnerability. Submit it as `HW{host}`.',
      flag: 'WOyNzZiTdUdf484B',
      workspace: () => {
        const r = random(55555);
        // Scan with several KEV findings, only some internet facing.
        const plants = [
          ['vpn01', '203.0.113.10', 'yes', 'CVE-2023-4966', '9.4'],
          ['portal09', '203.0.113.22', 'yes', 'CVE-2021-26855', '9.8'],
          ['web03', '203.0.113.31', 'yes', 'CVE-2026-40011', '9.6'],
          ['app11', '10.0.4.44', 'no', 'CVE-2021-44228', '10.0'],
          ['dc01', '10.0.1.10', 'no', 'CVE-2020-1472', '10.0'],
          ['mail07', '203.0.113.52', 'yes', 'CVE-2026-20771', '8.1']
        ];
        const scan = scanCsv(55555, { count: 50, plants });
        // IDS alerts: scanning everywhere, plus real exploit attempts against two KEV CVEs.
        const events = [];
        for (let i = 0; i < 80; i++) events.push(idsEvent(at(r.int(0, 23), r.int(0, 59)), { signature: 'Generic web scanner activity', cve: '-', src_ip: `192.0.2.${r.int(2, 200)}`, dest_host: r.pick(['vpn01', 'portal09', 'web03', 'mail07', 'shop01']), severity: 'low', action: 'detected' }));
        // Attempts against the Citrix flaw, but aimed at a host that is NOT the one carrying it in the scan (a decoy).
        for (let i = 0; i < 10; i++) events.push(idsEvent(at(r.int(9, 18), r.int(0, 59)), { signature: 'Citrix NetScaler session token disclosure', cve: 'CVE-2023-4966', src_ip: r.pick(['198.51.100.9', '203.0.113.88']), dest_host: 'vpn02', action: 'detected' }));
        // Real, matching attempts against portal09 for the Exchange flaw it actually has.
        for (let i = 0; i < 16; i++) events.push(idsEvent(at(r.int(10, 17), r.int(0, 59), r.int(0, 59)), { signature: 'Exchange SSRF access to internal endpoint', cve: 'CVE-2021-26855', src_ip: r.pick(['203.0.113.50', '198.51.100.9']), dest_host: 'portal09', action: 'detected' }));
        return {
          type: 'case',
          title: 'Scan and alerts',
          tabs: [
            { type: 'shell', title: 'Scan and KEV', cwd: '/home/learner', hostname: 'analyst', motd: 'scan.csv and kev.csv are here.\n', files: { '/home/learner/scan.csv': scan, '/home/learner/kev.csv': kevCsv(), '/home/learner/README.txt': 'scan.csv: host, ip, internet_facing, cve, cvss.\n' } },
            { type: 'siem', title: 'IDS alerts', events, start: 'index=ids' }
          ]
        };
      },
      hints: ['Work out three sets and find where they overlap: internet facing KEV findings in the scan, and the CVEs being attacked in the IDS.', 'From the scan, the internet facing KEV hosts are a short list. From the IDS, find which KEV CVE is being attacked and against which host.', 'Watch for a decoy: there are alerts for a KEV CVE, but aimed at a host that does not carry that CVE in the scan. You need the host where the vulnerability, the exposure and the attacks all line up.'],
      writeup: {
        how: 'In the scan, crossing against KEV and keeping internet facing rows gives vpn01 (CVE-2023-4966) and portal09 (CVE-2021-26855); web03 and mail07 are exposed but their CVEs are not on KEV, and app11 and dc01 are KEV but internal. In the IDS, two KEV related signatures fire: Citrix session token attempts, but aimed at vpn02, which does not carry that flaw in the scan, and Exchange SSRF attempts aimed at portal09, which does carry CVE-2021-26855. The host where vulnerable, exposed and under active attack all meet is portal09.',
        why: 'Each data source on its own over counts: lots of systems are vulnerable, lots are scanned, but the intersection is small and that is what demands action now. The Citrix alerts against vpn02 are a useful distraction, because a real analyst has to confirm that the thing being attacked is actually present and exposed, not just that an alert mentions a scary CVE.',
        fix: 'Emergency patch portal09 and hunt it for signs of successful exploitation, since it is being actively attacked. Then vpn01 as the other exposed KEV host, and check vpn02: it is being probed for a Citrix flaw, so confirm its real patch level rather than trusting that the scan missed nothing.'
      }
    }
  ]
};

