import { random, at, winEvent } from './helpers.js';
import { Capture } from './network.js';
import { pdf, zip } from './forensics.js';

// One incident at Larkfield on 13 March 2026, investigated end to end. Each
// challenge is a stage of the same story, using whichever evidence source an
// analyst would reach for, and the final one puts three sources side by side.
// Every piece of evidence is synthetic.

// A small raw email, headers then body, the way it reaches the mail gateway.
function rawEmail({ received, auth, from, replyTo, to, subject, date, id, html, text }) {
  const head = [
    `Received: ${received}`,
    `Authentication-Results: mx1.larkfield.example; ${auth}`,
    `From: ${from}`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${date}`,
    `Message-ID: <${id}>`,
    'MIME-Version: 1.0',
    `Content-Type: text/${html ? 'html' : 'plain'}; charset=utf-8`
  ];
  return `${head.join('\n')}\n\n${html ?? text}\n`;
}

const phishEmail = rawEmail({
  received: 'from mail.m365-billing.test (mail.m365-billing.test [198.51.100.77])\n\tby mx1.larkfield.example with ESMTPS id 7A1C; Fri, 13 Mar 2026 08:14:02 +0000',
  auth: 'spf=pass smtp.mailfrom=m365-billing.test;\n\tdkim=pass header.d=m365-billing.test; dmarc=fail header.from=larkfield.example',
  from: '"Larkfield Finance" <billing@larkfield.example>',
  replyTo: 'billing@m365-billing.test',
  to: 'm.garcia@larkfield.example',
  subject: 'Overdue invoice INV-55140 needs your approval today',
  date: 'Fri, 13 Mar 2026 08:14:00 +0000',
  id: 'inv55140@m365-billing.test',
  html: '<p>Hello Maria,</p><p>Invoice <b>INV-55140</b> is overdue and payment is on hold until it is approved. Review and approve it in the finance portal:</p><p><a href="https://finance.larkfield.example.pay-review.test/login?u=m.garcia@larkfield.example">https://finance.larkfield.example/invoices/55140</a></p><p>If you do not approve it today the supplier account will be suspended.</p><p>Larkfield Finance</p>'
});

// A couple of ordinary messages so the mailbox is not a single obvious phish.
const inboxExtras = [
  rawEmail({ received: 'from mail01.larkfield.example (mail01.larkfield.example [10.0.2.10])\n\tby mx1.larkfield.example with ESMTP id 1B2C; Fri, 13 Mar 2026 07:50:00 +0000', auth: 'spf=pass smtp.mailfrom=larkfield.example; dkim=pass header.d=larkfield.example; dmarc=pass header.from=larkfield.example', from: '"Priya Raman" <priya@larkfield.example>', to: 'm.garcia@larkfield.example', subject: 'Re: March close', date: 'Fri, 13 Mar 2026 07:49:59 +0000', id: 'close1@larkfield.example', text: 'Thanks Maria, numbers look good. Let us sign off this afternoon.' }),
  rawEmail({ received: 'from smtp.officesupplies.example (smtp.officesupplies.example [203.0.113.25])\n\tby mx1.larkfield.example with ESMTPS id 3D4E; Fri, 13 Mar 2026 08:02:00 +0000', auth: 'spf=pass smtp.mailfrom=officesupplies.example; dkim=pass header.d=officesupplies.example; dmarc=pass header.from=officesupplies.example', from: '"Office Supplies Ltd" <billing@officesupplies.example>', to: 'accounts@larkfield.example', subject: 'Statement for February', date: 'Fri, 13 Mar 2026 08:01:59 +0000', id: 'stmt-feb@officesupplies.example', text: 'Your February statement is attached. No action needed.' })
];

export default {
  id: 'capstone',
  title: 'Incident response capstone',
  short: 'Capstone',
  summary: 'Investigate one real feeling incident from start to finish: the phishing email, the stolen account, the beacon, the staged data and the exfiltration, across the mailbox, the SIEM, a packet capture and the host.',
  intro: 'This final topic is one incident, investigated the way a real response runs. Each challenge is a stage, and each uses whichever evidence an analyst would reach for. Everything you learned in the earlier topics comes together here, finishing with a single investigation that spans several evidence sources at once.',
  outcomes: [
    'Run an investigation across several evidence sources',
    'Carry an indicator from one source to the next',
    'Separate what an attacker attempted from what they achieved',
    'Reconstruct an incident timeline from scattered evidence',
    'Produce the facts a response and a write-up need'
  ],
  lessons: [
    {
      id: 'capstone-brief',
      title: 'The incident, and how to work it',
      summary: 'The response lifecycle, the Larkfield incident you are about to investigate, and how to pivot between sources.',
      minutes: 9,
      terms: [
        ['incident response', 'The organised handling of a security incident. A common model has six phases: preparation, identification, containment, eradication, recovery, and lessons learned.'],
        ['indicator', 'A concrete piece of evidence that ties activity together: an address, a domain, an account, a file hash, a host name. Also called an IOC.'],
        ['pivot', 'Taking an indicator found in one source and searching for it in another, to follow the attacker across systems.'],
        ['containment', 'Stopping the incident spreading or continuing, for example by isolating a host or disabling an account, before cleaning up.'],
        ['dwell time', 'How long an attacker was active before being caught. The timeline you build measures it.']
      ],
      workspace: { type: 'mail', title: 'Reported mailbox', messages: [phishEmail, ...inboxExtras], open: 0 },
      blocks: [
        { type: 'text', body: 'This topic is one incident at Larkfield, on 13 March 2026, investigated from the first report to the final picture. You will move through it in stages, and each stage uses a different kind of evidence: the mailbox, the SIEM, a packet capture, and the compromised host itself. The skill the capstone tests is not any single tool. It is carrying what you find in one source into the next.' },
        { type: 'text', body: 'Most teams follow a lifecycle with six phases. You do not march through them in a straight line, but they name the work.' },
        { type: 'table', head: ['Phase', 'What it means here'], rows: [['Preparation', 'The logging, captures and tools that made this investigation possible at all'], ['Identification', 'Confirming something happened and what it is'], ['Containment', 'Stopping it spreading: isolate hosts, disable accounts'], ['Eradication', 'Removing the attacker\'s access and tools'], ['Recovery', 'Restoring systems and watching for a return'], ['Lessons learned', 'The write-up and the changes that stop it next time']] },
        { type: 'text', body: 'The engine of an investigation is the **pivot**. You find an indicator in one place, a domain, an address, an account, and you search for it everywhere else. One phishing email becomes a stolen account, which becomes a compromised host, which becomes a destination data was sent to. Each answer is the next question\'s starting point.' },
        { type: 'text', body: 'The report that started this incident is on the right: a finance clerk, Maria Garcia, forwarded a suspicious invoice email. Open it and read it the way the email topic taught: the headers, the authentication results, and where the link really goes.' },
        { type: 'task', text: 'Open the reported invoice email and look at both its Headers and its Message.', check: (log) => log.some((e) => e.type === 'open-mail' && e.index === 0) && log.some((e) => e.type === 'mail-tab') },
        { type: 'quiz', question: 'The email shows From: billing@larkfield.example but `dmarc=fail`, and its link text and real target differ. Where should the investigation go after confirming it is a phish?', options: [
          { text: 'Find out whether Maria entered her credentials, and whether her account was then used', correct: true, why: 'A delivered phish is low impact until someone interacts. The next questions are whether she submitted her password and whether the attacker then logged in, which moves the investigation from the mailbox to the authentication logs.' },
          { text: 'Nothing. It failed DMARC, so the mail system handled it', why: 'DMARC failing does not undo a click that already happened. You have to check what followed.' },
          { text: 'Delete the email and close the ticket', why: 'Deleting the evidence before investigating is exactly the wrong move.' }
        ] },
        { type: 'note', title: 'Keep notes as you go', body: 'Write down every indicator and every time, in UTC, as you find it. The final stage of this capstone asks you to bring three sources together, and that is far easier when you have been recording the pieces all along.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'capstone-phish',
      title: 'Stage 1: the lure',
      difficulty: 'easy',
      points: 100,
      skills: ['phishing', 'URL anatomy', 'registered domains'],
      prepare: ['capstone-brief', 'email-links'],
      brief: 'Maria Garcia reported the invoice email. The security team needs the domain behind its link, so they can block it and search the proxy logs for anyone who visited it. The link text looks like Larkfield, as these always do.',
      goal: 'Find where the email\'s link really goes and submit its registered domain as `HW{domain}`.',
      flag: 'gQXvgVkajqBAex86eyD7BoROWg==',
      workspace: () => ({ type: 'mail', messages: [phishEmail, ...inboxExtras], open: 0 }),
      hints: ['The link text and the real target are different. The mailbox shows the real target in brackets.', 'Take the host name of the real link and read it from the right.', 'The host is `finance.larkfield.example.pay-review.test`. The registered domain is the last two labels.'],
      writeup: {
        how: 'The displayed link reads `https://finance.larkfield.example/invoices/55140`, but its real target is `https://finance.larkfield.example.pay-review.test/login?u=m.garcia@larkfield.example`. Reading the host name from the right, the top level domain is `.test` and the registered domain is `pay-review.test`. Everything to the left, including Larkfield\'s name, is a subdomain the attacker controls. The `u=` parameter even pre-fills Maria\'s address on the fake login page.',
        why: 'The registered domain is the indicator you can act on: block it, and search logs for it. The lookalike subdomain is designed so that anyone glancing at the start of the address trusts it.',
        fix: 'Block `pay-review.test`, search proxy logs for anyone who reached it, and check whether Maria submitted her password. The next stage follows the account.'
      }
    },
    {
      id: 'capstone-access',
      title: 'Stage 2: the stolen key',
      difficulty: 'medium',
      points: 150,
      skills: ['Windows logons', 'logon types', 'pivoting'],
      prepare: ['logs-windows'],
      brief: 'Proxy logs confirm Maria visited the phishing site and submitted a form. Her account may now be in someone else\'s hands. Larkfield staff reach internal systems through a remote access gateway, and almost everyone connects from inside the office network. Somewhere in today\'s logons, Maria\'s account was used from somewhere it should not have been.',
      goal: 'Find the external address that logged in as m.garcia and submit it as `HW{address}`.',
      flag: 'LPHMwacP9hQjb4uukNC4hQ==',
      workspace: () => {
        const r = random(614);
        const events = [];
        const staff = ['j.smith', 'a.khan', 'l.chen', 'r.oconnor', 'k.mensah', 'm.garcia', 'p.novak', 's.ito'];
        // Normal remote gateway logons: internal source addresses all day.
        for (let i = 0; i < 160; i++) {
          events.push(winEvent(at(7) + r.int(0, 11 * 3600) * 1000, 4624, { host: 'RAS01', user: r.pick(staff), logon_type: 10, src_ip: `10.0.5.${r.int(10, 90)}` }));
        }
        // Maria's own normal logons from her workstation's subnet.
        for (let i = 0; i < 6; i++) events.push(winEvent(at(8, r.int(0, 59)) + r.int(0, 2 * 3600) * 1000, 4624, { host: 'RAS01', user: 'm.garcia', logon_type: 10, src_ip: '10.0.5.22' }));
        // A few failed logons, internal, nothing special.
        for (let i = 0; i < 10; i++) events.push(winEvent(at(r.int(8, 17), r.int(0, 59)), 4625, { host: 'RAS01', user: r.pick(staff), logon_type: 10, src_ip: `10.0.5.${r.int(10, 90)}`, failure_reason: 'bad password' }));
        // The attacker: m.garcia, from an external address, just after the phish.
        events.push(winEvent(at(10, 2, 41), 4624, { host: 'RAS01', user: 'm.garcia', logon_type: 10, src_ip: '203.0.113.66' }));
        events.push(winEvent(at(10, 2, 42), 4672, { host: 'RAS01', user: 'm.garcia', privileges: 'SeRemoteInteractiveLogonRight' }));
        return { type: 'siem', events, start: 'index=windows EventCode=4624 user=m.garcia' };
      },
      hints: ['Every normal logon to the gateway comes from a 10.x internal address. Look for one that does not.', 'Filter to successful logons for m.garcia, then exclude the internal range.', '`index=windows EventCode=4624 user=m.garcia NOT src_ip=10.*` leaves the attacker\'s address.'],
      writeup: {
        how: 'Filtering successful gateway logons (4624) for m.garcia and excluding the internal `10.` range leaves one event: a remote interactive logon from `203.0.113.66` at 10:02:41, less than two hours after the phishing email. Every other logon for her, and for everyone else, comes from an internal workstation address.',
        why: 'Stolen credentials look exactly like the real user, because they are the real user\'s password. The giveaway is context: the same account, but from a place it never comes from. "Impossible travel" and "logon from a new location" detections are built on exactly this. The timing, right after the phish, confirms the link.',
        fix: 'Disable the account and force a password reset, and invalidate active sessions. Phishing resistant MFA, such as security keys, would have made the stolen password useless. The next stage follows what the attacker did once inside.'
      }
    },
    {
      id: 'capstone-beacon',
      title: 'Stage 3: checking in',
      difficulty: 'medium',
      points: 200,
      skills: ['packets', 'beaconing', 'timing'],
      prepare: ['net-patterns'],
      brief: 'From the gateway, the attacker reached Maria\'s workstation, WS-022 (10.0.5.22), and ran tooling on it. This is twenty minutes of traffic captured from that workstation. If something is running on it for the attacker, it will be calling home on a schedule.',
      goal: 'Find the external address WS-022 is beaconing to and how often, in whole seconds. Submit `HW{address_seconds}`.',
      flag: 'gAzlz+pI4QmfyWBHMvVkBG9z3Kau',
      workspace: () => {
        const c = new Capture(202);
        const ws = '10.0.5.22';
        // Ordinary encrypted traffic to known services.
        let t = 0.3;
        const sites = [['192.0.2.40', 'outlook.office.com'], ['192.0.2.41', 'teams.microsoft.com'], ['203.0.113.10', 'intranet.larkfield.example']];
        for (let i = 0; i < 20; i++) { const [ip, name] = c.r.pick(sites); c.dns(t, ws, '10.0.0.53', name, [ip]); t = c.tls(t + 0.03, ws, ip, name, { records: c.r.int(2, 5) }) + c.r.next() * 3; }
        // The beacon: the same external address every 45 seconds, tiny and regular.
        c.dns(2.0, ws, '10.0.0.53', 'cdn-sync.telemetry-edge.test', ['198.51.100.202']);
        for (let b = 2.4; b < 1200; b += 45 + (c.r.next() - 0.5) * 0.8) {
          c.tls(b, ws, '198.51.100.202', '', { records: 1, size: 280, port: 443 });
        }
        return { type: 'packets', packets: c.done() };
      },
      hints: ['A beacon is small, regular, and goes somewhere only this host talks to. Start with the Conversations view.', 'Find the external address this host contacts over and over, then filter to the first packet of each of its connections and look at the times.', 'Filter `ip.addr == 198.51.100.202 && tcp.flags.syn == 1 && tcp.flags.ack == 0`, then subtract consecutive start times.'],
      writeup: {
        how: 'Conversations shows ordinary traffic to Office and the intranet, and one external address, `198.51.100.202` (looked up as `cdn-sync.telemetry-edge.test`), contacted far more often than anything else. Filtering to the start of each of its connections gives times about 45 seconds apart, every one a tiny TLS session with no server name. That regular, small, nameless pattern is a command and control beacon.',
        why: 'The beacon is the clearest proof that the attacker has live control of WS-022, not just a one-off login. Its contents are encrypted, but its rhythm and destination give it away without needing to read anything. The 45 second interval and the destination are indicators to block and to hunt for on other hosts.',
        fix: 'Isolate WS-022 from the network, block the C2 address and domain, and hunt for the same beacon pattern elsewhere. The next stage looks at what the attacker did on the servers they could reach.'
      }
    },
    {
      id: 'capstone-stage',
      title: 'Stage 4: packing for the trip',
      difficulty: 'medium',
      points: 200,
      skills: ['forensics', 'file timelines', 'find'],
      prepare: ['forensics-timeline'],
      brief: 'Using Maria\'s access, the attacker reached the file server SRV-FILE01 and, the logs suggest, collected data into one place before taking it. You have a copy of a working folder from that server with its original timestamps. The attacker was active from about 10:00 UTC on 13 March. Anything created in that window, in a place it should not be, is what they staged.',
      goal: 'Find the archive the attacker created to stage the stolen data and submit its full path as `HW{path}`.',
      flag: 'CGn2tIB55nEADOlTKVl9TpjKGnon0xsH1DUZ0zsRGhoOgZVfDuCRhFFVxKg=',
      workspace: () => {
        const r = random(1322);
        const files = {};
        const old = (d, h, m) => Date.UTC(2026, 2, d, h, m, r.int(0, 59));
        // Normal shared files, created over the preceding weeks.
        for (let i = 0; i < 30; i++) files[`/share/finance/report_${String(i).padStart(2, '0')}.xlsx`] = { content: zip('xl/workbook.xml', `report ${i}`), mtime: old(r.int(1, 12), r.int(8, 17), r.int(0, 59)) };
        for (let i = 0; i < 12; i++) files[`/share/finance/invoices/inv_${5000 + i}.pdf`] = { content: pdf({ Title: `Invoice ${5000 + i}`, Author: 'finance' }), mtime: old(r.int(1, 12), r.int(8, 17), 0) };
        files['/share/finance/archive/2025-year-end.zip'] = { content: zip('data.csv', 'old'), mtime: old(1, 9, 0) };
        files['/share/finance/.DS_Store'] = { content: 'x', mtime: old(5, 10, 0) };
        // A backup job that legitimately writes a dated archive at 02:00.
        files['/share/finance/backups/finance-2026-03-13.zip'] = { content: zip('backup', 'nightly'), mtime: Date.UTC(2026, 2, 13, 2, 0, 11) };
        // The attacker's staging: a hidden folder and a big archive, created mid-morning.
        files['/share/finance/.tmp/'] = { owner: 'root', mtime: Date.UTC(2026, 2, 13, 10, 18, 3) };
        files['/share/finance/.tmp/customers-export.zip'] = { content: zip('customers.csv', 'customer_id,name,email\n'.repeat(40)), mtime: Date.UTC(2026, 2, 13, 10, 41, 52) };
        return { type: 'shell', cwd: '/share/finance', hostname: 'SRV-FILE01', motd: 'Copy of the finance share from SRV-FILE01, original timestamps kept.\n', files };
      },
      hints: ['The attacker was active from around 10:00 on 13 March. find can select files by modification time, and do not forget hidden folders.', '`find /share -type f -newermt "2026-03-13 10:00"` lists what changed in the window. The nightly backup at 02:00 is outside it.', 'One archive was created mid-morning in a hidden folder. `ls -a` shows the folder; the file inside it is the answer.'],
      writeup: {
        how: '`find /share -type f -newermt "2026-03-13 10:00"` returns one file: `/share/finance/.tmp/customers-export.zip`, created at 10:41 UTC inside a hidden `.tmp` folder owned by root. The nightly `finance-2026-03-13.zip` is a legitimate backup, but it was written at 02:00, outside the incident window. The hidden folder and the mid-morning timing both mark the archive as the attacker\'s staging.',
        why: 'Attackers collect data into one archive before taking it, which is both easier and faster to move. That staging archive, created in the incident window in an unusual place, is a key artefact: it tells you what was targeted (a customer export) and gives you a time to anchor the timeline.',
        fix: 'Preserve the archive as evidence and open it to confirm exactly what was collected. File integrity monitoring and alerts on new archives in share folders would have flagged this as it happened. The next stage finds where it was sent.'
      }
    },
    {
      id: 'capstone-exfil',
      title: 'Stage 5: out the door',
      difficulty: 'hard',
      points: 250,
      skills: ['packets', 'conversations', 'exfiltration'],
      prepare: ['net-patterns'],
      brief: 'The staged archive left the network shortly after it was created. This is traffic captured from SRV-FILE01 around that time. The nightly backup also ships data out, so volume alone is not the answer. Find where the attacker sent the data, which will be somewhere the server has no reason to talk to.',
      goal: 'Find the external host the archive was uploaded to and the port used, and submit `HW{address_port}`.',
      flag: 'DQHJm9SU8maYasH8g8to1tcOrK9EQ7U=',
      workspace: () => {
        const c = new Capture(541);
        const srv = '10.0.3.8';
        // The nightly backup still trickling: large, to the backup provider, on 443.
        c.session(1, srv, '203.0.113.150', c.port(), 443, Array.from({ length: 120 }, () => [true, '', 'Application Data', { app: 'TLS', tls: { type: 'Application Data' }, len: 1514 }]).concat([[false, '', 'Application Data', { app: 'TLS', len: 120 }]]), { gap: 0.03 });
        // Normal database replication to another internal server.
        for (let i = 0; i < 20; i++) c.session(c.r.next() * 30, srv, '10.0.3.15', c.port(), 1433, [[true, '', 'TDS', { len: 400 }], [false, '', 'TDS', { len: 600 }]]);
        // The exfiltration: a big upload to an external host on an unusual port, almost nothing back.
        c.dns(40.0, srv, '10.0.0.53', 'upload.file-drop-share.test', ['198.51.100.240']);
        c.session(40.2, srv, '198.51.100.240', c.port(), 8088, Array.from({ length: 260 }, () => [true, '', 'Continuation', { len: 1514 }]).concat([[false, '', 'Continuation', { len: 66 }]]), { gap: 0.04 });
        return { type: 'packets', packets: c.done() };
      },
      hints: ['Open Conversations and sort by bytes. More than one conversation is large.', 'Which large flows are explained (the backup on 443, internal replication) and which go to an odd place on an odd port? Check which side is sending.', 'Filter the suspicious pair for large packets and look at the source and destination port. The upload goes to port 8088.'],
      writeup: {
        how: 'Conversations shows three sizeable flows: the nightly backup to 203.0.113.150 on 443, internal database replication to 10.0.3.15, and a large upload from the server to `198.51.100.240` (looked up as `upload.file-drop-share.test`) on port 8088, with almost nothing coming back. The backup is expected and uses 443; the replication is internal. The upload to an unknown host on a non standard port, right after the archive was staged, is the exfiltration.',
        why: 'Volume on its own is normal on a file server. What makes this exfiltration is the combination: a large outbound transfer, to a destination the server never normally uses, on an unusual port, with a one sided ratio, at the time the staged archive existed. Each fact alone is weak; together they are conclusive.',
        fix: 'Block the destination and treat the customer data as breached, which may trigger notification obligations. Restricting server egress to known destinations and alerting on large uploads to new hosts would have stopped or caught this. The final stage ties the whole incident together.'
      }
    },
    {
      id: 'capstone-timeline',
      title: 'Stage 6: the whole picture',
      difficulty: 'hard',
      points: 300,
      skills: ['correlation', 'multiple sources', 'reporting'],
      prepare: ['logs-timeline'],
      brief: 'The write-up needs the incident in one line: who was phished, which host the attacker controlled, and where it called home. Those three facts live in three different places, open together here: the reported mailbox, the SIEM, and the packet capture from the compromised workstation. Pull one fact from each.',
      goal: 'Submit `HW{account_host_c2address}`: the phished account (its user name before the @), the host the attacker ran code on, and the command and control address it beaconed to. For example `HW{j.smith_WS-101_203.0.113.9}`.',
      flag: '2iXYUnZaTnITDNGxzrQG/0dZdTB3QRPd3UFXC6ZxWv7Iug==',
      workspace: () => {
        // The SIEM tab: process creation showing the attacker's tooling on WS-022,
        // plus ordinary activity, so the host is found, not guessed.
        const r = random(306);
        const events = [];
        const hosts = ['WS-011', 'WS-014', 'WS-022', 'WS-031', 'WS-040'];
        const normal = [['explorer.exe', 'chrome.exe'], ['explorer.exe', 'outlook.exe'], ['explorer.exe', 'excel.exe'], ['services.exe', 'svchost.exe']];
        for (let i = 0; i < 180; i++) { const [parent, process] = r.pick(normal); events.push(winEvent(at(8) + r.int(0, 9 * 3600) * 1000, 4688, { host: r.pick(hosts), user: r.pick(['j.smith', 'a.khan', 'l.chen']), process, parent_process: parent })); }
        // The attacker's tooling on WS-022, as m.garcia, flagged by the EDR.
        events.push(winEvent(at(10, 9, 2), 4688, { host: 'WS-022', user: 'm.garcia', process: 'rundll32.exe', parent_process: 'powershell.exe', command_line: 'rundll32.exe C:\\Users\\m.garcia\\AppData\\Local\\Temp\\s.dll,Start' }));
        events.push(winEvent(at(10, 9, 3), 4688, { host: 'WS-022', user: 'm.garcia', process: 'net.exe', parent_process: 'cmd.exe', command_line: 'net use \\\\SRV-FILE01\\finance' }));
        const siem = { type: 'siem', title: 'SIEM (process creation)', events, start: 'index=windows EventCode=4688 user=m.garcia' };
        // The packet capture tab from WS-022: the beacon, so the C2 is found here.
        const c = new Capture(306);
        const ws = '10.0.5.22';
        let t = 0.3;
        for (let i = 0; i < 12; i++) t = c.tls(t + 0.03, ws, '192.0.2.40', 'outlook.office.com', { records: 3 }) + c.r.next() * 2;
        c.dns(1.5, ws, '10.0.0.53', 'cdn-sync.telemetry-edge.test', ['198.51.100.202']);
        for (let b = 2.0; b < 600; b += 45) c.tls(b, ws, '198.51.100.202', '', { records: 1, size: 280 });
        const pcap = { type: 'packets', title: 'Capture from the host', packets: c.done() };
        return { type: 'case', title: 'All the evidence', tabs: [{ type: 'mail', title: 'Reported mailbox', messages: [phishEmail, ...inboxExtras] }, siem, pcap] };
      },
      hints: ['One fact per tab. The mailbox gives the account, the SIEM gives the host, the capture gives the C2 address.', 'In the SIEM, `index=windows EventCode=4688 user=m.garcia` shows the attacker\'s tooling and which host it ran on. In the capture, find the regular external beacon.', 'Account is the To address of the phish without the domain; host is where the m.garcia 4688 events ran; C2 is the address the host beacons to in the capture.'],
      writeup: {
        how: 'Each tab gives one fact. The mailbox shows the phish was addressed to `m.garcia@larkfield.example`, so the account is `m.garcia`. The SIEM, filtered to process creation for that user, shows suspicious tooling (`rundll32.exe` launched from PowerShell, then `net use` to the file share) running on `WS-022`. The capture from that host shows a regular beacon to `198.51.100.202`. Put together: m.garcia was phished, the attacker ran code on WS-022, and it called home to 198.51.100.202.',
        why: 'No single source tells the whole story. The mailbox has the lure but not the outcome; the SIEM has the host but not the network destination; the capture has the beacon but not who was targeted. Correlating them is what turns scattered alerts into one incident with a timeline, which is the core of incident response and of the report that follows.',
        fix: 'The write-up now has the one line summary and the indicators: the account, the host, the C2 address and domain, the staging archive and the exfiltration destination from the earlier stages. Containment (account disabled, host isolated, destinations blocked) and the lessons, phishing resistant MFA and tighter egress control, follow from it.'
      }
    }
  ]
};
