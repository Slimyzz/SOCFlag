import { random } from './helpers.js';
import { utf8, toBase64, toHex } from '../assets/js/lib/bytes.js';

// Builds packet captures as lists of decoded packets, roughly the way
// Wireshark would show them. Times are seconds from the start of the capture.
export class Capture {
  constructor(seed) {
    this.r = random(seed);
    this.packets = [];
    this.nextPort = 49152 + this.r.int(0, 2000);
  }
  port() {
    this.nextPort += this.r.int(1, 9);
    return this.nextPort;
  }
  add(packet) {
    this.packets.push({ ttl: packet.src.startsWith('10.') ? 128 : 52, ...packet });
    return packet;
  }
  tcp(t, src, sport, dst, dport, flags, extra = {}) {
    const len = extra.payload ? 54 + extra.payload.length : extra.len ?? 54;
    return this.add({ t, src, dst, proto: 'TCP', sport, dport, flags, len, info: extra.info ?? `${sport} → ${dport} [${flags}]${flags === 'SYN' ? ' Seq=0 Win=64240 Len=0' : ''}`, ...extra });
  }
  // A full TCP conversation: handshake, data in both directions, then close.
  // exchanges are [fromClient, payload, info, extra] in order.
  session(t, client, server, sport, dport, exchanges, { app, gap = 0.02, close = true } = {}) {
    this.tcp(t, client, sport, server, dport, 'SYN');
    this.tcp(t + 0.001, server, dport, client, sport, 'SYN, ACK', { info: `${dport} → ${sport} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0` });
    this.tcp(t + 0.002, client, sport, server, dport, 'ACK', { info: `${sport} → ${dport} [ACK] Seq=1 Ack=1 Len=0` });
    let now = t + 0.003;
    for (const [fromClient, payload, info, extra = {}] of exchanges) {
      now += gap * (0.5 + this.r.next());
      const [a, ap, b, bp] = fromClient ? [client, sport, server, dport] : [server, dport, client, sport];
      this.tcp(now, a, ap, b, bp, 'PSH, ACK', { app, payload, info, ...extra });
    }
    if (close) {
      this.tcp(now + 0.01, client, sport, server, dport, 'FIN, ACK', { info: `${sport} → ${dport} [FIN, ACK]` });
      this.tcp(now + 0.011, server, dport, client, sport, 'FIN, ACK', { info: `${dport} → ${sport} [FIN, ACK]` });
      this.tcp(now + 0.012, client, sport, server, dport, 'ACK', { info: `${sport} → ${dport} [ACK]` });
    }
    return now + 0.012;
  }
  dns(t, client, server, qname, answers = [], { qtype = 'A', rcode = 'No error' } = {}) {
    const id = `0x${this.r.int(0, 65535).toString(16).padStart(4, '0')}`;
    const sport = this.port();
    this.add({ t, src: client, dst: server, proto: 'UDP', app: 'DNS', sport, dport: 53, len: 74 + qname.length, info: `Standard query ${id} ${qtype} ${qname}`, dns: { id, qname, qtype } });
    const failed = rcode !== 'No error';
    this.add({ t: t + 0.004 + this.r.next() * 0.02, src: server, dst: client, proto: 'UDP', app: 'DNS', sport: 53, dport: sport, len: 90 + qname.length + answers.length * 16, info: `Standard query response ${id} ${failed ? `${rcode} ` : ''}${qtype} ${qname}${answers.map((a) => ` ${qtype} ${a}`).join('')}`, dns: { id, qname, qtype, response: true, answers, rcode } });
  }
  http(t, client, server, { host, method = 'GET', uri = '/', status = 200, reason = 'OK', type = 'text/html', body = '<html><body>ok</body></html>', ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0', headers = [], requestBody = '' }) {
    const request = `${method} ${uri} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${ua}\r\n${headers.map((h) => `${h}\r\n`).join('')}${requestBody ? `Content-Length: ${requestBody.length}\r\n` : ''}\r\n${requestBody}`;
    const response = `HTTP/1.1 ${status} ${reason}\r\nServer: nginx\r\nContent-Type: ${type}\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
    return this.session(t, client, server, this.port(), 80, [
      [true, request, `${method} ${uri} HTTP/1.1`, { http: { method, host, uri, ua } }],
      [false, response, `HTTP/1.1 ${status} ${reason}  (${type})`, { http: { status } }]
    ], { app: 'HTTP' });
  }
  tls(t, client, server, sni, { records = 2, size = 900, port = 443, version = 'TLS 1.3' } = {}) {
    const sport = this.port();
    const exchanges = [
      [true, '', `Client Hello${sni ? ` (SNI=${sni})` : ''}`, { tls: { type: 'Client Hello', sni, version }, len: 571 }],
      [false, '', 'Server Hello, Change Cipher Spec, Application Data', { tls: { type: 'Server Hello', version }, len: 1514 }]
    ];
    for (let i = 0; i < records; i++) exchanges.push([i % 2 === 0, '', 'Application Data', { tls: { type: 'Application Data' }, len: Math.min(1514, size) }]);
    return this.session(t, client, server, sport, port, exchanges, { app: 'TLS' });
  }
  done() {
    return this.packets.sort((a, b) => a.t - b.t).map((p) => ({ ...p, t: Math.round(p.t * 1e6) / 1e6 }));
  }
}

// The office capture shared by the lessons: a few minutes of ordinary traffic
// with a handful of things worth noticing.
function officeCapture() {
  const c = new Capture(42);
  const r = c.r;
  const dnsServer = '10.0.0.53';
  const sites = [['www.larkfield.example', '203.0.113.10'], ['outlook.office.com', '192.0.2.40'], ['teams.microsoft.com', '192.0.2.41'], ['github.com', '192.0.2.50'], ['www.wikipedia.org', '198.51.100.30']];
  let t = 0.2;
  for (let i = 0; i < 14; i++) {
    const client = r.pick(['10.0.5.21', '10.0.5.33', '10.0.5.40']);
    const [name, ip] = r.pick(sites);
    c.dns(t, client, dnsServer, name, [ip]);
    t = c.tls(t + 0.03, client, ip, name, { records: r.int(2, 5) }) + r.next() * 2;
  }
  // The intranet over plain HTTP, with a login.
  c.dns(3.1, '10.0.5.21', dnsServer, 'intranet.larkfield.example', ['10.0.1.80']);
  c.http(3.15, '10.0.5.21', '10.0.1.80', { host: 'intranet.larkfield.example', uri: '/', body: '<html><h1>Larkfield intranet</h1></html>' });
  c.http(5.4, '10.0.5.21', '10.0.1.80', { host: 'intranet.larkfield.example', method: 'POST', uri: '/login', type: 'text/html', requestBody: 'username=priya&password=Lunch4Friday!', body: '<html>Welcome back, Priya</html>' });
  // An FTP login to the old file server.
  c.session(8.0, '10.0.5.33', '10.0.1.21', c.port(), 21, [
    [false, '220 files01 FTP server ready\r\n', 'Response: 220 files01 FTP server ready'],
    [true, 'USER tom\r\n', 'Request: USER tom'],
    [false, '331 Password required for tom\r\n', 'Response: 331 Password required for tom'],
    [true, 'PASS Kettle-2026\r\n', 'Request: PASS Kettle-2026'],
    [false, '230 User tom logged in\r\n', 'Response: 230 User tom logged in'],
    [true, 'RETR rota.xlsx\r\n', 'Request: RETR rota.xlsx'],
    [false, '150 Opening data connection\r\n226 Transfer complete\r\n', 'Response: 150 Opening data connection'],
    [true, 'QUIT\r\n', 'Request: QUIT']
  ], { app: 'FTP' });
  // A machine scanning a server.
  t = 12;
  for (const port of [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]) {
    const sport = 40000 + port;
    t += 0.004;
    c.tcp(t, '10.0.5.99', sport, '10.0.1.20', port, 'SYN');
    if ([22, 80, 445].includes(port)) {
      c.tcp(t + 0.001, '10.0.1.20', port, '10.0.5.99', sport, 'SYN, ACK', { info: `${port} → ${sport} [SYN, ACK] Seq=0 Ack=1` });
      c.tcp(t + 0.002, '10.0.5.99', sport, '10.0.1.20', port, 'RST', { info: `${sport} → ${port} [RST] Seq=1` });
    } else {
      c.tcp(t + 0.001, '10.0.1.20', port, '10.0.5.99', sport, 'RST, ACK', { info: `${port} → ${sport} [RST, ACK] Seq=1 Ack=1` });
    }
  }
  // Odd DNS from one workstation: random names that do not exist.
  t = 15;
  for (let i = 0; i < 8; i++) {
    const name = `${Array.from({ length: r.int(12, 18) }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[r.int(0, 35)]).join('')}.info.test`;
    c.dns(t += 0.4, '10.0.5.40', dnsServer, name, [], { rcode: 'No such name' });
  }
  c.dns(t + 0.4, '10.0.5.40', dnsServer, 'k3j9x0aq2v7mz1.info.test', ['198.51.100.200']);
  // A ping.
  c.add({ t: 18.0, src: '10.0.5.21', dst: '10.0.1.80', proto: 'ICMP', len: 98, info: 'Echo (ping) request id=0x0001, seq=1/256' });
  c.add({ t: 18.001, src: '10.0.1.80', dst: '10.0.5.21', proto: 'ICMP', len: 98, info: 'Echo (ping) reply id=0x0001, seq=1/256' });
  return c.done();
}

function lessonCapture() {
  return { type: 'packets', packets: officeCapture() };
}

function filtered(log, test) {
  return log.some((e) => e.type === 'filter' && test(e.filter.toLowerCase().replace(/\s+/g, ' ').trim(), e));
}

export default {
  id: 'network',
  title: 'Network traffic analysis',
  short: 'Network',
  summary: 'Read packet captures, follow TCP conversations, recognise scans, read DNS, recover what cleartext protocols give away, and spot beaconing and data leaving the network.',
  intro: 'Logs record what systems decided to write down. A packet capture records what actually crossed the wire. This topic teaches you to read captures the way an analyst using Wireshark does, from single packets up to the traffic patterns that give attackers away.',
  outcomes: [
    'Read the packet list and the layers of a single packet',
    'Write display filters to find the traffic that matters',
    'Recognise the TCP handshake and the shape of a port scan',
    'Read DNS and spot tunnelling and generated domain names',
    'Recover credentials and files from cleartext protocols',
    'Find beaconing and unusually large transfers'
  ],
  lessons: [
    {
      id: 'net-basics',
      title: 'Reading a packet capture',
      summary: 'Packets, layers, addresses and ports, and your first display filters.',
      minutes: 12,
      terms: [
        ['packet', 'One unit of data sent over a network, with headers saying where it came from and where it is going.'],
        ['packet capture', 'A recording of packets seen on a network, usually saved as a .pcap file and opened in Wireshark or similar tools.'],
        ['port', 'A number that says which program on a machine a packet is for. Web servers listen on 80 and 443, DNS on 53, SSH on 22.'],
        ['display filter', 'An expression that hides every packet that does not match, like `dns` or `ip.addr == 10.0.1.80`.'],
        ['protocol layers', 'Each packet is wrapped in layers: the network link, then IP (addresses), then TCP or UDP (ports), then the application, such as DNS or HTTP.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'Everything a computer sends over a network is broken into **packets**. A **packet capture** records them, with exact times, so you can replay a conversation afterwards. The viewer on the right works like Wireshark, the standard tool for this: a list of packets at the top, details of the selected packet below, and a hex view of its raw bytes.' },
        { type: 'table', head: ['Column', 'Meaning'], rows: [['No.', 'Position in the capture'], ['Time', 'Seconds since the capture started'], ['Source and Destination', 'IP addresses of sender and receiver'], ['Protocol', 'The highest layer the viewer understood, such as DNS or TLS'], ['Length', 'Size of the packet in bytes'], ['Info', 'A one line summary']] },
        { type: 'text', body: 'Each packet has layers, like an envelope inside an envelope. **IP** carries the addresses. **TCP** or **UDP** carries the **ports**, which say which program the data is for. Inside that is the application data itself. Click a packet to see its layers.' },
        { type: 'task', text: 'Click any packet in the list and look at its layers in the details pane.', check: (log) => log.filter((e) => e.type === 'select-packet').length > 1 },
        { type: 'table', head: ['Port', 'Usually means'], rows: [['53', 'DNS'], ['80', 'HTTP (web, unencrypted)'], ['443', 'HTTPS (web over TLS)'], ['21', 'FTP (file transfer, unencrypted)'], ['22', 'SSH'], ['23', 'Telnet (remote login, unencrypted)'], ['25', 'SMTP (email between servers)'], ['445', 'SMB (Windows file sharing)'], ['3389', 'RDP (Remote Desktop)']] },
        { type: 'text', body: 'A capture of a few minutes on a busy network can have millions of packets, so you will rarely scroll. **Display filters** hide everything that does not match. They read like small sentences.' },
        { type: 'example', title: 'Display filters', steps: [
          { cmd: 'dns', note: 'Only DNS packets. A protocol name on its own is a filter.' },
          { cmd: 'ip.addr == 10.0.1.80', note: 'Packets to or from one address. `ip.src` and `ip.dst` pick one direction.' },
          { cmd: 'tcp.port == 21', note: 'Packets where either port is 21.' },
          { cmd: 'ip.addr == 10.0.5.21 && http', note: '`&&` means and, `||` means or, `!` means not.' },
          { cmd: '!tls && !dns', note: 'Hide the encrypted web traffic and DNS to see what is left.' }
        ] },
        { type: 'task', text: 'Apply a filter that shows only DNS traffic.', check: (log) => filtered(log, (f) => f === 'dns' || f.includes('udp.port == 53')) },
        { type: 'task', text: 'Show only traffic to or from the intranet server, `10.0.1.80`.', check: (log) => filtered(log, (f) => f.includes('10.0.1.80')) },
        { type: 'quiz', question: 'Which filter shows packets sent by 10.0.5.33, but not packets sent to it?', options: [
          { text: '`ip.src == 10.0.5.33`', correct: true, why: '`ip.src` matches only the sender. `ip.addr` matches either end.' },
          { text: '`ip.addr == 10.0.5.33`', why: 'That matches traffic in both directions.' },
          { text: '`ip.dst == 10.0.5.33`', why: 'That is the opposite: packets sent to it.' }
        ] },
        { type: 'note', title: 'Capture filters and display filters', body: 'Wireshark has two kinds. Capture filters decide what gets recorded in the first place and use a different syntax. Display filters, like the ones here, only change what you see in a capture you already have.' }
      ]
    },
    {
      id: 'net-tcp',
      title: 'TCP handshakes and scans',
      summary: 'SYN, SYN-ACK and ACK, what a reset means, and how a port scan looks on the wire.',
      minutes: 12,
      terms: [
        ['three way handshake', 'How a TCP connection starts: the client sends SYN, the server replies SYN, ACK, and the client confirms with ACK.'],
        ['RST', 'Reset. A packet that refuses or abruptly ends a connection. A closed port answers a SYN with RST.'],
        ['port scan', 'Probing many ports to find which ones accept connections. On the wire, many SYNs from one source to many ports.'],
        ['SYN scan', 'A scan that sends SYN, notes the reply, and never completes the handshake. Also called a half open scan.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'TCP is the protocol under most of the traffic you care about: web, email, file sharing, remote login. Before any data moves, the two sides agree to talk with a **three way handshake**. The `Info` column shows the flags of each packet in square brackets.' },
        { type: 'code', body: '10.0.5.21 → 10.0.1.80  [SYN]       "I would like to connect to port 80"\n10.0.1.80 → 10.0.5.21  [SYN, ACK]  "Port 80 is open, go ahead"\n10.0.5.21 → 10.0.1.80  [ACK]       "Connected"', caption: 'Every TCP connection begins like this.' },
        { type: 'task', text: 'Filter for the intranet web traffic (`ip.addr == 10.0.1.80 && tcp.port == 80`) and find a handshake at the start of a connection.', check: (log) => filtered(log, (f) => f.includes('10.0.1.80') && f.includes('80')) },
        { type: 'text', body: 'If nothing listens on the port, the server answers a SYN with **RST** instead. If a firewall drops the packet, there is no answer at all. So the reply to a SYN tells you whether a port is open, closed or filtered, which is exactly what a **port scan** is trying to learn.' },
        { type: 'table', head: ['Reply to SYN', 'Port is'], rows: [['SYN, ACK', 'Open: something is listening'], ['RST, ACK', 'Closed: the machine is there, nothing is listening'], ['Nothing', 'Filtered: a firewall dropped it, or the machine is down']] },
        { type: 'task', text: 'Find the scan. Show every SYN without an ACK, which is the first packet of each connection attempt.', hint: '`tcp.flags.syn == 1 && tcp.flags.ack == 0`', check: (log) => filtered(log, (f) => f.includes('tcp.flags.syn == 1') && f.includes('tcp.flags.ack == 0')) },
        { type: 'text', body: 'One address, `10.0.5.99`, sends SYNs to fifteen different ports on `10.0.1.20` in a fraction of a second. Normal clients connect to one or two well known ports. Many ports from one source in a short burst is the signature of a scan. Notice also that after each SYN, ACK, the scanner sends RST rather than ACK: it never finishes the handshake.' },
        { type: 'task', text: 'Find out which ports on 10.0.1.20 are open by filtering for its SYN, ACK replies.', hint: '`ip.src == 10.0.1.20 && tcp.flags.syn == 1 && tcp.flags.ack == 1`', check: (log) => filtered(log, (f) => f.includes('ip.src == 10.0.1.20') && f.includes('syn') && f.includes('ack == 1')) },
        { type: 'answer', question: 'Which three ports were open on 10.0.1.20? List them in order, separated by commas.', accept: ['22, 80, 445', '22,80,445', '22 80 445'], hint: 'Read the source port of each SYN, ACK reply.', explain: 'SSH, web and Windows file sharing. A scanner now knows exactly what to try next, and so do you: these are the services to check for exposure and patches.' },
        { type: 'quiz', question: 'The scan came from inside the network, from 10.0.5.99. Why is that more worrying than a scan from the internet?', options: [
          { text: 'Internal scanning often means an attacker already controls a machine and is looking for the next one', correct: true, why: 'Internet scans are constant background noise. A workstation scanning its own network is a classic sign of lateral movement, unless it is an approved scanner, which you should be able to check.' },
          { text: 'Internal scans are faster', why: 'Speed is not the issue. Who is scanning, and why, is.' },
          { text: 'It is not more worrying', why: 'Unless the machine is an approved vulnerability scanner, it should never be probing other machines.' }
        ] }
      ]
    },
    {
      id: 'net-dns',
      title: 'DNS',
      summary: 'Queries and answers, record types, and the DNS patterns that point to malware: tunnelling and generated names.',
      minutes: 12,
      terms: [
        ['DNS', 'Domain Name System. Turns names like larkfield.example into IP addresses. Almost every connection starts with a DNS lookup.'],
        ['NXDOMAIN', 'The DNS answer "no such name". Shown as "No such name" here.'],
        ['DGA', 'Domain generation algorithm. Malware that computes many random looking names each day and tries them until one resolves to its operator\'s server.'],
        ['DNS tunnelling', 'Hiding data inside DNS queries and answers, for example as long encoded subdomains, to get it through networks that allow DNS but block everything else.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'Before a machine connects to a name, it asks DNS for the address. That makes DNS logs and captures a list of everywhere a machine intended to go, including places it never reached. Each lookup is a query from the client and a response from the DNS server.' },
        { type: 'example', title: 'DNS filters', steps: [
          { cmd: 'dns', note: 'All DNS packets.' },
          { cmd: 'dns.flags.response == 0', note: 'Only the questions.' },
          { cmd: 'dns.qry.name contains larkfield', note: 'Questions or answers about a particular name.' }
        ] },
        { type: 'table', head: ['Record type', 'Answer it gives'], rows: [['A', 'An IPv4 address'], ['AAAA', 'An IPv6 address'], ['CNAME', 'Another name to look up instead'], ['MX', 'The mail servers for a domain'], ['TXT', 'Free text. Used for SPF and domain verification, and abused for tunnelling']] },
        { type: 'task', text: 'Show only DNS queries (not responses) and scroll through them. Which machine is asking for strange names?', check: (log) => filtered(log, (f) => f.includes('dns.flags.response == 0')) },
        { type: 'text', body: '`10.0.5.40` asks for eight random looking names under `info.test`, and every one fails with "No such name". Then the ninth works. That pattern is a **DGA**: malware generating names until it finds the one its operator registered today. Blocking one domain does not help much, because tomorrow it will be a different name.' },
        { type: 'quiz', question: 'What makes DGA traffic stand out in DNS?', options: [
          { text: 'Many failed lookups for long, random looking names from one machine', correct: true, why: 'Normal browsing looks up real names that mostly exist. A burst of NXDOMAIN answers for names nobody could type is a strong signal, and many DNS security tools score names on how random they look.' },
          { text: 'It uses a different port from normal DNS', why: 'It uses normal DNS on port 53, which is why it gets through.' },
          { text: 'The answers are encrypted', why: 'Ordinary DNS is not encrypted. The names themselves are the giveaway.' }
        ] },
        { type: 'text', body: '**DNS tunnelling** abuses the fact that most networks let DNS out. Data is encoded into the names being looked up, such as `6c61726b.data.attacker.test`, and the attacker\'s DNS server, which receives every lookup for its domain, collects the pieces. Signs: very long names, many unique subdomains under one domain, hex or Base64 looking labels, and lots of TXT queries.' },
        { type: 'predict', question: 'A host makes 4,000 queries in an hour, all for different subdomains of one domain, each a 60 character hex string. What is the most likely explanation?', options: [
          { text: 'Data being smuggled out through DNS', correct: true, why: 'Real services do not need thousands of unique, encoded subdomains. Each query carries a chunk of data to whoever runs the domain\'s DNS server.' },
          { text: 'A slow DNS server causing retries', why: 'Retries repeat the same name. These are all different.' },
          { text: 'Normal browsing', why: 'Browsing produces repeated lookups of a modest number of real names.' }
        ] },
        { type: 'note', title: 'DNS logs are worth keeping', body: 'Even without full captures, logging every DNS query and answer at your resolvers gives you most of this visibility. Encrypted DNS (DNS over HTTPS) inside browsers can bypass those resolvers, which is why many organisations configure it centrally.' }
      ]
    },
    {
      id: 'net-cleartext',
      title: 'Cleartext protocols',
      summary: 'Following a TCP stream, and how much HTTP, FTP and similar protocols give away to anyone on the path.',
      minutes: 12,
      terms: [
        ['cleartext', 'Data sent without encryption. Anyone who can see the traffic can read it.'],
        ['follow stream', 'Putting all the packets of one TCP connection together and showing the conversation as text, client and server in different colours.'],
        ['HTTP Basic authentication', 'Sending a user name and password in an `Authorization: Basic` header, encoded with Base64. Without TLS, that is effectively plain text.'],
        ['FTP', 'File Transfer Protocol. An old protocol that sends user names, passwords and files without encryption.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'Older protocols were designed for networks where everyone was trusted. HTTP, FTP, Telnet, POP3, IMAP and SMTP all have unencrypted forms, and in those forms every password and every file crosses the network as readable text. Captures make that very easy to see.' },
        { type: 'text', body: 'Single packets only show fragments. **Follow stream** collects every packet in one TCP connection and shows the conversation as text. Select a packet, then press Follow stream.' },
        { type: 'task', text: 'Filter for `ftp`, select one of the packets, and follow its stream.', check: (log) => log.some((e) => e.type === 'follow') && filtered(log, (f) => f.includes('ftp') || f.includes('21')) },
        { type: 'answer', question: 'What password did tom use to log in to the FTP server?', accept: ['Kettle-2026'], hint: 'Look for the line starting with PASS in the followed stream.', explain: 'Anyone able to capture traffic on that network segment, or on any network the traffic crosses, has the same view. FTP should be replaced by SFTP or FTPS.' },
        { type: 'task', text: 'Now find the HTTP request that sends a login form to the intranet.', hint: 'Filter with `http.request.method == POST`, then select the packet and read its payload, or follow the stream.', check: (log) => filtered(log, (f) => f.includes('post')) },
        { type: 'text', body: 'The intranet login posts `username=priya&password=...` over plain HTTP. Internal sites are often left on HTTP because "it is only internal", but an attacker with a foothold on the internal network is exactly who can capture it.' },
        { type: 'quiz', question: 'An internal app uses HTTP Basic authentication over plain HTTP. The header is `Authorization: Basic cHJpeWE6THVuY2g0RnJpZGF5IQ==`. How protected is the password?', options: [
          { text: 'Not at all. Base64 decodes to `priya:Lunch4Friday!` without any key', correct: true, why: 'Base64 is an encoding, not encryption. Basic authentication is only acceptable over TLS, where the whole request is encrypted.' },
          { text: 'Well protected, because it is encoded', why: 'Anyone can decode Base64. Try it in the Tools page.' },
          { text: 'Protected, because it is a header and not the body', why: 'Headers are just as visible as the body in cleartext HTTP.' }
        ] },
        { type: 'note', title: 'Where cleartext still hides', body: 'Printers, cameras, building systems, old file servers and internal admin pages are the usual places. Captures from a span port or network tap for an hour will usually find some of them.' }
      ]
    },
    {
      id: 'net-tls',
      title: 'What encryption still shows',
      summary: 'What TLS hides, what it does not, and why defenders still get value from encrypted traffic.',
      minutes: 9,
      terms: [
        ['TLS', 'Transport Layer Security. Encrypts traffic between client and server. The S in HTTPS.'],
        ['SNI', 'Server Name Indication. The name of the site the client wants, sent unencrypted in the Client Hello in most connections today.'],
        ['metadata', 'Everything about a connection apart from its contents: who, where, when, how much and how often.'],
        ['JA3', 'A fingerprint of how a client builds its TLS Client Hello. Malware often has a distinctive one.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'Most traffic today is encrypted with **TLS**, and that is good: nobody on the path can read your email or passwords. But encryption hides the contents, not the fact that a conversation happened. Analysts still see a great deal.' },
        { type: 'table', head: ['Hidden by TLS', 'Still visible'], rows: [['Page contents, files, form data', 'Source and destination addresses and ports'], ['URL paths and parameters', 'The site name in the SNI, in most connections'], ['Cookies and passwords', 'When the connection happened and how long it lasted'], ['', 'How many bytes went each way'], ['', 'The DNS lookup before it, unless DNS is encrypted too']] },
        { type: 'task', text: 'Filter for TLS Client Hello packets and read the server names.', hint: 'Try `tls.handshake.extensions_server_name contains .` or just `tls` and look at the Info column.', check: (log) => filtered(log, (f) => f.includes('tls')) },
        { type: 'quiz', question: 'A workstation sends 300 MB to an unfamiliar address over TLS at 3am. You cannot see the contents. Is that worth investigating?', options: [
          { text: 'Yes. Volume, timing and destination are evidence on their own', correct: true, why: 'Large uploads at odd hours to a destination nobody else uses is a classic exfiltration pattern. You do not need to read the data to know it left, how much, and where it went.' },
          { text: 'No. If it is encrypted, there is nothing to see', why: 'The metadata alone tells a story, and it is often enough to start a host investigation.' },
          { text: 'Only if the SNI is missing', why: 'A present SNI does not make it safe; a missing one is just one more odd detail.' }
        ] },
        { type: 'note', title: 'Inspection', body: 'Some organisations decrypt outbound TLS at a proxy so security tools can see inside. It is powerful but has real privacy and security costs, and many sites, such as banking and health, are usually exempted. Metadata analysis works without it.' }
      ]
    },
    {
      id: 'net-patterns',
      title: 'Unusual traffic patterns',
      summary: 'Beaconing, large uploads, odd ports and rare destinations, and the conversations view.',
      minutes: 11,
      terms: [
        ['conversation', 'All the traffic between two addresses. Summarising by conversation shows who talks to whom and how much.'],
        ['beaconing', 'Regular, small check ins from an infected machine to its controller, often at a fixed interval.'],
        ['exfiltration', 'Moving data out of an organisation without permission.'],
        ['baseline', 'What normal looks like for a network: usual destinations, volumes, ports and times. Anomalies only make sense against one.']
      ],
      workspace: lessonCapture(),
      blocks: [
        { type: 'text', body: 'Individual packets rarely give an attacker away on their own. Patterns do. The most useful patterns to know are about **who talks to whom**, **how much**, **how regularly**, and **on which ports**.' },
        { type: 'table', head: ['Pattern', 'Why it stands out'], rows: [['Beaconing', 'Small connections at regular intervals, day and night, to the same place'], ['Large outbound transfer', 'Much more data going out than coming in, often at night'], ['Unusual port', 'Common protocols on odd ports, or odd protocols on common ones'], ['Rare destination', 'An address only one machine in the company ever contacts'], ['Internal scanning', 'One host touching many hosts or ports']] },
        { type: 'text', body: 'The **Conversations** view summarises the displayed packets by pair of addresses, with packet and byte counts, sorted by bytes. It is the quickest way to see where the volume is.' },
        { type: 'task', text: 'Open the Conversations view for the whole capture.', check: (log) => log.some((e) => e.type === 'conversations') },
        { type: 'text', body: 'In a short capture like this one, the biggest conversations are ordinary web traffic. In a real investigation you would compare this against a baseline: the same view from a normal day. A pair that never appears normally, or carries ten times its usual volume, is where you look first.' },
        { type: 'predict', question: 'A host connects to the same external address every 60 seconds, each time sending about 300 bytes and receiving about 150, around the clock. What does that suggest?', options: [
          { text: 'Beaconing to a command and control server', correct: true, why: 'Fixed intervals, fixed sizes and no break at night are what automated check ins look like. Many legitimate update agents also check in regularly, so the next step is to see whether the destination is known and expected.' },
          { text: 'Someone browsing the web', why: 'People do not browse at exact 60 second intervals all night.' },
          { text: 'A large file download', why: 'The amounts are tiny. Downloads move far more data.' }
        ] },
        { type: 'order', question: 'Put these steps for checking a suspected beacon in a sensible order.', items: ['Find the regular connections and their interval', 'Check whether the destination is known and expected for that host', 'Check whether other hosts talk to the same destination', 'Look at the host itself for the process making the connections'], explain: 'Network evidence tells you something is wrong and where. The host tells you what and how. The two together make the case.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'net-ftp-creds',
      title: 'Passwords on the wire',
      difficulty: 'easy',
      points: 100,
      skills: ['ftp', 'follow stream', 'cleartext'],
      prepare: ['net-cleartext'],
      brief: 'Larkfield still runs an old FTP server for its backup jobs. The infrastructure team says it is fine because "the password is strong". You have been asked to show what an attacker on the network would see during one backup run.',
      goal: 'Find the password the backup job sends to the FTP server and submit it as `SOC{password}`.',
      flag: 'kOZN3fGtffXkdSasU/Ltr/7yhzmlDyRT',
      workspace: () => {
        const c = new Capture(21);
        let t = 0.1;
        for (let i = 0; i < 10; i++) t = c.tls(t + c.r.next(), `10.0.5.${c.r.int(20, 60)}`, '192.0.2.40', 'outlook.office.com', { records: 3 }) + 0.2;
        c.dns(2.0, '10.0.9.5', '10.0.0.53', 'files01.larkfield.example', ['10.0.1.21']);
        c.session(2.1, '10.0.9.5', '10.0.1.21', c.port(), 21, [
          [false, '220 files01 FTP server ready\r\n', 'Response: 220 files01 FTP server ready'],
          [true, 'USER svc_backup\r\n', 'Request: USER svc_backup'],
          [false, '331 Password required for svc_backup\r\n', 'Response: 331 Password required for svc_backup'],
          [true, 'PASS Tr0ub4dor&Backup!77\r\n', 'Request: PASS Tr0ub4dor&Backup!77'],
          [false, '230 User svc_backup logged in\r\n', 'Response: 230 User svc_backup logged in'],
          [true, 'TYPE I\r\n', 'Request: TYPE I'],
          [false, '200 Type set to I\r\n', 'Response: 200 Type set to I'],
          [true, 'STOR nightly-2026-03-13.tar.gz\r\n', 'Request: STOR nightly-2026-03-13.tar.gz'],
          [false, '150 Ok to send data\r\n226 Transfer complete\r\n', 'Response: 150 Ok to send data'],
          [true, 'QUIT\r\n', 'Request: QUIT'],
          [false, '221 Goodbye\r\n', 'Response: 221 Goodbye']
        ], { app: 'FTP' });
        return { type: 'packets', packets: c.done() };
      },
      hints: ['FTP sends its commands as plain text. Filter for the protocol first.', 'Apply the filter `ftp`, select a packet and press Follow stream to see the whole conversation.', 'The password follows the word PASS.'],
      writeup: {
        how: 'Filtering for `ftp` and following the stream shows the whole login: `USER svc_backup`, then `PASS Tr0ub4dor&Backup!77`, then the server confirming the login and accepting the upload of the nightly backup. No decoding is needed.',
        why: 'A strong password does nothing if it crosses the network in the clear. Anyone with access to the path, through a compromised machine, a misconfigured switch port or a rogue access point, can collect it. Service accounts like this one are especially valuable because their passwords rarely change and they often have broad access.',
        fix: 'Replace FTP with SFTP or FTPS, rotate the password now that it has been exposed, and restrict the backup account so it can only write to its own folder.'
      }
    },
    {
      id: 'net-scan',
      title: 'Knocking on doors',
      difficulty: 'easy',
      points: 100,
      skills: ['tcp flags', 'SYN scan', 'display filters'],
      prepare: ['net-tcp'],
      brief: 'The network team captured traffic after an alert about a workstation probing the server range. The scan covered many ports on the database server, `10.0.3.15`. Before the server is checked, you need to know which ports the scanner found open.',
      goal: 'Find every port on 10.0.3.15 that answered the scan as open. Submit them in ascending order joined by underscores, as `SOC{port_port_port}`.',
      flag: 'VDlBDt9+mHcm4zUCn7JBsjvV9YbHKA==',
      workspace: () => {
        const c = new Capture(1433);
        const open = [22, 1433, 5985, 8443];
        const ports = [...new Set([...Array.from({ length: 60 }, () => c.r.int(1, 10000)), ...open, 80, 443, 3389, 445])].sort(() => c.r.next() - 0.5);
        let t = 1;
        for (const port of ports) {
          const sport = 51000 + (port % 500);
          t += 0.003 + c.r.next() * 0.004;
          c.tcp(t, '10.0.5.87', sport, '10.0.3.15', port, 'SYN');
          if (open.includes(port)) {
            c.tcp(t + 0.0008, '10.0.3.15', port, '10.0.5.87', sport, 'SYN, ACK', { info: `${port} → ${sport} [SYN, ACK] Seq=0 Ack=1` });
            c.tcp(t + 0.0011, '10.0.5.87', sport, '10.0.3.15', port, 'RST', { info: `${sport} → ${port} [RST] Seq=1` });
          } else if (port === 445 || port === 3389) {
            // Filtered by the host firewall: no reply at all.
          } else {
            c.tcp(t + 0.0008, '10.0.3.15', port, '10.0.5.87', sport, 'RST, ACK', { info: `${port} → ${sport} [RST, ACK] Seq=1 Ack=1` });
          }
        }
        // Real application traffic to the database at the same time.
        for (let i = 0; i < 6; i++) {
          c.session(0.5 + i * 0.9, `10.0.2.${30 + i}`, '10.0.3.15', c.port(), 1433, [[true, '', 'TDS7 pre-login message', { len: 120 }], [false, '', 'TDS7 response', { len: 140 }]]);
        }
        return { type: 'packets', packets: c.done() };
      },
      hints: ['An open port answers a SYN with SYN, ACK. A closed one answers with RST.', 'Filter for packets from the server that have both the SYN and ACK flags set.', '`ip.src == 10.0.3.15 && tcp.flags.syn == 1 && tcp.flags.ack == 1`, then read the source ports. Make sure each one is a reply to the scanner, not to normal clients.'],
      writeup: {
        how: 'Filtering for `ip.src == 10.0.3.15 && tcp.flags.syn == 1 && tcp.flags.ack == 1` shows the server accepting connections. Some of those are normal clients connecting to SQL Server on 1433. Limiting to replies sent to the scanner (`&& ip.dst == 10.0.5.87`) leaves four ports: 22 (SSH), 1433 (SQL Server), 5985 (Windows remote management) and 8443 (often an admin web interface). Ports 445 and 3389 got no reply at all, which means they are filtered, not closed.',
        why: 'An internal scan is reconnaissance: whoever controls 10.0.5.87 now has a list of services to attack. Knowing exactly what they found tells you which services to check for weak passwords, missing patches and unexpected exposure, and whether 5985 and 8443 should be reachable from workstations at all.',
        fix: 'Isolate and investigate the scanning workstation. Restrict the database server so only application servers can reach it, and alert on any host contacting more than a handful of ports or hosts in a short time.'
      }
    },
    {
      id: 'net-download',
      title: 'A picture that was not',
      difficulty: 'medium',
      points: 150,
      skills: ['http', 'follow stream', 'content types', 'file signatures'],
      prepare: ['net-cleartext', 'forensics-signatures'],
      brief: 'Endpoint protection on WS-022 quarantined a new program minutes after the user opened an email. Proxy logs show only image downloads from that machine at the time, all over plain HTTP. One of those "images" was not an image.',
      goal: 'Find the HTTP download whose content is really a Windows program and submit the full request path (the URI) as `SOC{path}`.',
      flag: 'ox4FOx7qR0BT6JHJWFwbS6Xo1hXsM+o3tedgmg==',
      workspace: () => {
        const c = new Capture(2222);
        const ws = '10.0.5.22';
        const img = (sig) => sig + 'x'.repeat(c.r.int(200, 600));
        const downloads = [
          ['static.newsfeed.test', '/img/header.png', 'image/png', img('\x89PNG\r\n\x1a\n')],
          ['static.newsfeed.test', '/img/logo.png', 'image/png', img('\x89PNG\r\n\x1a\n')],
          ['cdn.photos.test', '/u/3381/photo.jpg', 'image/jpeg', img('\xff\xd8\xff\xe0')],
          ['img.invoice-preview.test', '/preview/7731/page1.png', 'image/png', `MZ\x90\x00\x03\x00\x00\x00${'This program cannot be run in DOS mode.'}${'x'.repeat(300)}`],
          ['cdn.photos.test', '/u/3382/photo.jpg', 'image/jpeg', img('\xff\xd8\xff\xe0')],
          ['static.newsfeed.test', '/img/banner.gif', 'image/gif', img('GIF89a')]
        ];
        let t = 0.5;
        for (const [host, uri, type, body] of downloads) {
          const ip = { 'static.newsfeed.test': '198.51.100.81', 'cdn.photos.test': '198.51.100.82', 'img.invoice-preview.test': '203.0.113.209' }[host];
          c.dns(t, ws, '10.0.0.53', host, [ip]);
          t = c.http(t + 0.02, ws, ip, { host, uri, type, body }) + 0.3 + c.r.next();
        }
        for (let i = 0; i < 12; i++) t = c.tls(t + c.r.next(), `10.0.5.${c.r.int(20, 60)}`, '192.0.2.41', 'teams.microsoft.com', { records: 2 });
        return { type: 'packets', packets: c.done() };
      },
      hints: ['Filter for HTTP responses and look at what each one actually contains, not what its Content-Type header claims.', 'Select each HTTP response packet and look at the first bytes of the body in the hex view, or follow each stream.', 'A Windows program starts with `MZ`. Find that response, then take the path from the request in the same stream.'],
      writeup: {
        how: 'Filtering for `http` shows six request and response pairs, all declaring image content types. Following each stream, five bodies start with the expected signatures (`PNG`, `JFIF`, `GIF89a`). The response for `/preview/7731/page1.png` from `img.invoice-preview.test` declares `image/png` but its body starts with `MZ` and contains "This program cannot be run in DOS mode": it is a Windows executable.',
        why: 'Malware delivery often disguises executables as images to get past proxies and filters that trust content types or extensions. Checking the actual bytes, here directly in the capture, confirms what was delivered and gives you a domain and path to block and to search for on other machines.',
        fix: 'Block the domain, search proxy logs for any other machine that fetched it, and configure the proxy or gateway to inspect file signatures rather than trusting declared types.'
      }
    },
    {
      id: 'net-dns-tunnel',
      title: 'Talking in lookups',
      difficulty: 'medium',
      points: 200,
      skills: ['dns', 'tunnelling', 'hex decoding'],
      prepare: ['net-dns'],
      brief: 'The firewall blocks all outbound traffic from the finance network except DNS to the internal resolver. Someone still managed to get data out. The DNS resolver logs show one workstation making a lot of unusual lookups this morning.',
      goal: 'Find the domain used for tunnelling, put the smuggled data back together in order, decode it, and submit the flag.',
      flag: 'WWnRpgXTfH/TMVi4AKa4a494siki5AXyBI2K7T4i0cWfEmHEag==',
      workspace: (flag) => {
        const c = new Capture(53);
        const resolver = '10.0.0.53';
        const normal = [['www.larkfield.example', '203.0.113.10'], ['outlook.office.com', '192.0.2.40'], ['login.microsoftonline.com', '192.0.2.42'], ['www.bbc.co.uk', '198.51.100.30'], ['update.larkfield.example', '203.0.113.11']];
        let t = 0.1;
        for (let i = 0; i < 40; i++) {
          const [name, ip] = c.r.pick(normal);
          c.dns(t += c.r.next() * 0.8, `10.0.6.${c.r.int(10, 40)}`, resolver, name, [ip]);
        }
        const secret = toHex(utf8(`finance export ok. ${flag}`));
        const chunks = secret.match(/.{1,24}/g);
        t = 3;
        chunks.forEach((chunk, i) => {
          c.dns(t += 0.6 + c.r.next(), '10.0.6.23', resolver, `${String(i).padStart(2, '0')}.${chunk}.s.cdn-telemetry.test`, ['10.0.0.1'], { qtype: 'A' });
        });
        // A noisy but legitimate service with long names.
        for (let i = 0; i < 10; i++) c.dns(t - 5 + i * 0.7, '10.0.6.31', resolver, `${toHex(utf8(String(i * 7919))).slice(0, 8)}.license-check.larkfield.example`, ['203.0.113.12']);
        return { type: 'packets', packets: c.done() };
      },
      hints: ['Filter for DNS queries and look for names that no person would type. Then narrow it down to one domain.', 'Use `dns.qry.name contains cdn-telemetry` and `dns.flags.response == 0`. Each name starts with a sequence number, then a chunk of hex.', 'Copy the hex chunks in sequence order, join them, and use Hex decode on the Tools page.'],
      writeup: {
        how: 'Among ordinary lookups, `10.0.6.23` asks for names like `00.66696e616e636520657870.s.cdn-telemetry.test`. The first label is a sequence number and the second is hex. Filtering with `dns.qry.name contains cdn-telemetry && dns.flags.response == 0` lists them in order. Joining the hex chunks and decoding gives "finance export ok." followed by the flag. The long names under `license-check.larkfield.example` are a real licensing service: Larkfield\'s own domain, from a different host, with short labels that do not decode to text.',
        why: 'DNS is allowed out of almost every network, because nothing works without it. Whoever runs the authoritative DNS server for `cdn-telemetry.test` receives every lookup for it, so each query delivers a chunk of data even though the workstation never connects to anything outside. It is slow, but enough for passwords, keys and small files.',
        fix: 'Only let the internal resolvers talk to the internet, log every query, and alert on long, high entropy labels and on large numbers of unique subdomains under one domain. Many DNS security services do this automatically.'
      }
    },
    {
      id: 'net-smtp',
      title: 'Sent to a personal address',
      difficulty: 'medium',
      points: 200,
      skills: ['smtp', 'follow stream', 'cleartext'],
      prepare: ['net-cleartext'],
      brief: 'A data loss alert says a large attachment left through Larkfield\'s old internal mail relay, which still accepts plain SMTP on port 25. Three messages went out through it in the capture window. HR needs to know where the customer list was sent.',
      goal: 'Find the message carrying the customer list and submit the recipient\'s email address as `SOC{address}`.',
      flag: 'vMS1i4spV+2jI+bwaSw7krsc1MLDMaiPrIM4FBYpPhQF',
      workspace: () => {
        const c = new Capture(25);
        const relay = '10.0.1.25';
        const mail = (t, client, from, to, subject, attachment) => c.session(t, client, relay, c.port(), 25, [
          [false, '220 relay01.larkfield.example ESMTP\r\n', 'S: 220 relay01.larkfield.example ESMTP'],
          [true, 'EHLO ws\r\n', 'C: EHLO ws'],
          [false, '250-relay01 Hello\r\n250 OK\r\n', 'S: 250-relay01 Hello'],
          [true, `MAIL FROM:<${from}>\r\n`, `C: MAIL FROM:<${from}>`],
          [false, '250 OK\r\n', 'S: 250 OK'],
          [true, `RCPT TO:<${to}>\r\n`, `C: RCPT TO:<${to}>`],
          [false, '250 Accepted\r\n', 'S: 250 Accepted'],
          [true, 'DATA\r\n', 'C: DATA'],
          [false, '354 Enter message\r\n', 'S: 354 Enter message'],
          [true, `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/octet-stream; name="${attachment}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${toBase64(utf8(attachment.endsWith('.csv') ? 'customer_id,name,email,phone\n1001,Example Customer,customer@example.test,555-0100\n' : 'report body'))}\r\n--b--\r\n.\r\n`, `C: DATA fragment, ${subject}`],
          [false, '250 Queued\r\n', 'S: 250 Queued'],
          [true, 'QUIT\r\n', 'C: QUIT']
        ], { app: 'SMTP' });
        let t = 0.3;
        for (let i = 0; i < 8; i++) t = c.tls(t + c.r.next(), `10.0.5.${c.r.int(20, 60)}`, '192.0.2.40', 'outlook.office.com', { records: 3 });
        mail(2.0, '10.0.5.31', 'printer-3f@larkfield.example', 'facilities@larkfield.example', 'Toner low', 'status.txt');
        mail(4.5, '10.0.5.44', 'r.oconnor@larkfield.example', 'r.oconnor.home@freemail.test', 'stuff for the weekend', 'customers_full_2026.csv');
        mail(6.1, '10.0.5.12', 'reports@larkfield.example', 'finance@larkfield.example', 'Daily sales', 'sales_0313.pdf');
        return { type: 'packets', packets: c.done() };
      },
      hints: ['SMTP is plain text when it is not wrapped in TLS. Filter for it.', 'Follow each SMTP stream. Look at the RCPT TO line and the attachment names.', 'The message with a .csv attachment named after customers is the one. Its RCPT TO line gives the recipient.'],
      writeup: {
        how: 'Filtering for `smtp` and following each of the three streams shows the full message, including headers and the Base64 attachment. A printer status email and a sales report go to internal addresses. The third, from `r.oconnor@larkfield.example` with subject "stuff for the weekend", attaches `customers_full_2026.csv` and is addressed to `r.oconnor.home@freemail.test`. Decoding the attachment confirms customer records.',
        why: 'Insiders sending data to personal accounts is one of the most common data loss cases, and it is usually careless rather than malicious. Cleartext SMTP made this easy to reconstruct from the network alone, but it also means anyone else on the path could have read the customer data.',
        fix: 'Require TLS on internal relays, stop internal relays from delivering to external domains, and have data loss prevention rules block or quarantine customer data going to personal addresses.'
      }
    },
    {
      id: 'net-beacon',
      title: 'Every sixty seconds',
      difficulty: 'hard',
      points: 250,
      skills: ['conversations', 'timing analysis', 'beaconing'],
      prepare: ['net-patterns', 'net-tls'],
      brief: 'This is fifteen minutes of traffic from the server VLAN. The servers here should only talk to each other, to the update server and to a monitoring service. One of them has been talking to somewhere else, quietly and on a schedule.',
      goal: 'Find the external address the beaconing server talks to and how often, in whole seconds. Submit `SOC{address_seconds}`.',
      flag: 'XqUXrBqKj/I2v5ihvIKloWpArSD2',
      workspace: () => {
        const c = new Capture(60);
        const servers = ['10.0.3.11', '10.0.3.12', '10.0.3.15', '10.0.3.20', '10.0.3.21'];
        for (let t = 2; t < 900; t += 30 + c.r.next() * 20) {
          c.session(t, c.r.pick(servers), c.r.pick(servers), c.port(), 1433, [[true, '', 'TDS7 query', { len: 300 + c.r.int(0, 800) }], [false, '', 'TDS7 response', { len: 400 + c.r.int(0, 1100) }]]);
        }
        for (const server of servers) {
          for (let t = 5 + c.r.next() * 20; t < 900; t += 120) c.tls(t + c.r.next() * 3, server, '203.0.113.30', 'metrics.monitoring.example.com', { records: 2, size: 700 });
        }
        c.tls(300, '10.0.3.12', '203.0.113.11', 'update.larkfield.example', { records: 8, size: 1514 });
        c.tls(310, '10.0.3.20', '203.0.113.11', 'update.larkfield.example', { records: 8, size: 1514 });
        for (let t = 11.4; t < 900; t += 60 + (c.r.next() - 0.5) * 0.6) {
          c.tls(t, '10.0.3.21', '198.51.100.66', '', { records: 2, size: 320, port: 443 });
        }
        return { type: 'packets', packets: c.done() };
      },
      hints: ['Start with the Conversations view. Which external addresses appear, and are they expected?', 'Filter for one suspicious pair and only the first packet of each connection: `ip.addr == X && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Then look at the times.', 'Subtract consecutive start times. The interval is close to a round number of seconds.'],
      writeup: {
        how: 'Conversations shows internal database traffic, every server talking to the monitoring service at 203.0.113.30 every two minutes, two servers fetching updates from 203.0.113.11, and one pair that does not fit: 10.0.3.21 and 198.51.100.66. Filtering for its SYN packets gives fifteen connections whose start times are about 60 seconds apart, each with a TLS Client Hello that carries no server name and a few hundred bytes of data.',
        why: 'Command and control traffic is usually encrypted, so its contents tell you nothing. Its rhythm and destination do. A server VLAN is a good place to hunt, because the set of legitimate destinations is small and stable, so anything new stands out.',
        fix: 'Block the address, isolate 10.0.3.21 and investigate the host. Restrict server egress to an allow list of known destinations, which would have stopped this connection entirely.'
      }
    },
    {
      id: 'net-exfil',
      title: 'Out the door',
      difficulty: 'hard',
      points: 300,
      skills: ['conversations', 'frame.len', 'unusual ports', 'exfiltration'],
      prepare: ['net-patterns'],
      brief: 'Overnight, the internet link from the office was unusually busy for about a minute. Backups go to a cloud provider at night, so busy is not automatically bad. Something else also sent a lot of data out, to a destination nothing at Larkfield should talk to.',
      goal: 'Find the internal host that uploaded data to an unexpected destination, and the destination port it used. Submit `SOC{host_port}`.',
      flag: 'XpnW/O9hKgz3Xe02usWi/WrjAQ==',
      workspace: () => {
        const c = new Capture(4444);
        // The nightly backup: big, expected, to the backup provider on 443.
        c.session(1, '10.0.9.5', '203.0.113.150', c.port(), 443, Array.from({ length: 420 }, (_, i) => [true, '', 'Application Data', { app: 'TLS', tls: { type: 'Application Data' }, len: 1514 }]).concat([[false, '', 'Application Data', { app: 'TLS', tls: { type: 'Application Data' }, len: 120 }]]), { gap: 0.04 });
        // Workstations idling.
        for (let i = 0; i < 12; i++) c.tls(c.r.next() * 40, `10.0.5.${c.r.int(20, 60)}`, '192.0.2.40', 'outlook.office.com', { records: 2 });
        // The exfiltration: a workstation pushing data to an unusual port.
        c.dns(14.9, '10.0.5.61', '10.0.0.53', 'sync.files-mirror.test', ['198.51.100.240']);
        c.session(15, '10.0.5.61', '198.51.100.240', c.port(), 8088, Array.from({ length: 310 }, () => [true, '', 'Continuation', { len: 1514 }]).concat([[false, '', 'Continuation', { len: 66 }]]), { gap: 0.05 });
        // Downloads look big too, but they come in rather than go out.
        c.session(20, '10.0.5.33', '198.51.100.31', c.port(), 443, Array.from({ length: 200 }, () => [false, '', 'Application Data', { app: 'TLS', tls: { type: 'Application Data' }, len: 1514 }]), { gap: 0.03 });
        return { type: 'packets', packets: c.done() };
      },
      hints: ['Conversations, sorted by bytes, shows where the volume is. More than one conversation is large.', 'Which large conversations are explained by the brief, and which go in the wrong direction or to an odd place? Check who is sending the big packets.', 'Filter each large pair with `frame.len > 1000` and look at the source. One sends lots of full sized packets out to a port that is not 443.'],
      writeup: {
        how: 'Conversations sorted by bytes shows three big pairs. 10.0.9.5 to 203.0.113.150 on 443 is the nightly backup. 10.0.5.33 and 198.51.100.31 is large but the full sized packets come from outside, so it is a download. 10.0.5.61 sends about 310 full sized packets to 198.51.100.240 on port 8088, after looking up `sync.files-mirror.test`, with almost nothing coming back. That is roughly 470 KB uploaded from a workstation to an unknown host on an unusual port.',
        why: 'Volume alone is not suspicious, because backups and downloads are big. Direction, destination and port turn volume into evidence: a workstation uploading far more than it receives, to a host nobody else uses, on a non standard port. Exfiltration detections built on those combinations catch real cases without alerting on every backup.',
        fix: 'Block the destination, isolate 10.0.5.61 and find out what was sent. Limit outbound traffic from workstations to the ports and proxies they need, and alert on large upload ratios to new destinations.'
      }
    }
  ]
};
