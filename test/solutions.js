// The intended way to solve every challenge, written as code. The tests run
// each one against the challenge's own workspace to prove it can be solved
// that way, and the author scripts use them to derive answer flags (flags
// such as SOC{address_count} that come from the generated data).
import { createMachine } from '../assets/js/shell/index.js';
import { runQuery } from '../assets/js/lib/query.js';
import { parseMessage } from '../assets/js/lib/mime.js';
import { compileFilter } from '../assets/js/ui/packets.js';
import { fromBase64, text } from '../assets/js/lib/bytes.js';
import { sha256 } from '../assets/js/lib/hash.js';
import { hms } from '../content/helpers.js';
import { punycodeToUnicode } from '../assets/js/ui/tools.js';

// The address a Received header says the connection came from.
const receivedIp = (value) => /\[(\d+\.\d+\.\d+\.\d+)\]\)/.exec(value)[1];
const receivedHeaders = (m) => m.headers.filter((h) => h.name === 'Received').map((h) => h.value);
const registered = (host) => host.split('.').slice(-2).join('.');
const hrefs = (html) => [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);

// What a learner has to work with, for any kind of workspace.
export function toolkit(spec) {
  let machine = null;
  return {
    spec,
    tab: (i) => toolkit(spec.tabs[i]),
    sh(line) {
      machine ??= createMachine(spec);
      return machine.shell.execute(line).chunks.map((c) => c.text).join('').replace(/[[0-9;]*m/g, '');
    },
    query: (q) => runQuery(spec.events, q).rows,
    packets: (filter = '') => spec.packets.filter(compileFilter(filter)),
    mail: () => spec.messages.map(parseMessage),
    decodeBase64: (value) => text(fromBase64(value)),
    decodeUtf16: (value) => String.fromCharCode(...fromBase64(value).filter((_, i) => i % 2 === 0)),
    sha256,
    hms
  };
}

export const solutions = {
  // Linux fundamentals
  'linux-hidden-note': ({ sh }) => sh('ls -a /srv/projects/handover; cat /srv/projects/handover/.handover'),
  'linux-needle': ({ sh }) => sh('grep -r "SOC{" /var/log/app'),
  'linux-exact-size': ({ sh }) => sh('cat $(find /srv/backup -type f -size 1337c)'),
  'linux-locked-out': ({ sh }) => sh('chmod 600 ~/vault/key.txt; cat ~/vault/key.txt'),
  'linux-top-talker': ({ sh }) => {
    const [count, ip] = sh('grep " 401 " access.log | cut -d" " -f1 | sort | uniq -c | sort -rn | head -n 1').trim().split(/\s+/);
    return `SOC{${ip}_${count}}`;
  },
  'linux-firmware': ({ sh }) => sh('strings camera.bin | grep support_key | cut -d= -f2 | base64 -d'),
  'linux-history': ({ sh }) => sh('cat /home/jordan/.bash_history; cat /tmp/.cache-7f3a/q3-final.txt'),
  'linux-groups': ({ sh }) => sh('id; cat $(find / -group auditors -type f 2>/dev/null)'),
  'linux-layers': ({ sh }) => sh('cat blob.txt | xxd -r -p | rev | base64 -d'),

  // Log investigation
  'logs-overnight': ({ query }) => {
    const top = query('index=linux action=failure | stats count by src_ip | sort -count | head 1')[0];
    const user = query(`index=linux action=failure src_ip=${top.src_ip} | top user limit=1`)[0].user;
    return `SOC{${top.src_ip}_${user}}`;
  },
  'logs-web-scanner': ({ query }) => {
    const scanner = query('index=web | stats count by src_ip | sort -count | head 1')[0].src_ip;
    return `SOC{${query(`index=web src_ip=${scanner} status=200 | table uri`)[0].uri}}`;
  },
  'logs-spray': ({ query }) => {
    const row = query('index=windows EventCode=4625 | stats count, dc(user) as accounts by src_ip | sort -accounts | head 1')[0];
    return `SOC{${row.src_ip}_${row.accounts}}`;
  },
  'logs-got-in': ({ query }) => {
    const row = query('index=linux action=success auth_method=password NOT src_ip=10.*')[0];
    return `SOC{${row.user}_${hms(row._time)}}`;
  },
  'logs-new-admin': ({ query }) => {
    const row = query('index=windows EventCode=4732 group=Administrators')[0];
    return `SOC{${row.user}_${row.subject_user}}`;
  },
  'logs-encoded': ({ query, decodeUtf16 }) => {
    const row = query('index=windows EventCode=4688 process=powershell.exe parent_process=winword.exe')[0];
    const decoded = decodeUtf16(row.command_line.split(' ').pop());
    return `SOC{${/https?:\/\/([^/]+)/.exec(decoded)[1]}}`;
  },
  'logs-beacon': ({ query }) => {
    const row = query('index=proxy | stats count, dc(src_host) as hosts, dc(bytes_out) as sizes by dest_host | where hosts = 1 | where sizes = 1 | sort -count | head 1')[0];
    const host = query(`index=proxy dest_host=${row.dest_host} | top src_host limit=1`)[0].src_host;
    return `SOC{${host}_${row.dest_host}}`;
  },

  // Email and phishing
  'email-origin': ({ mail }) => `SOC{${receivedIp(receivedHeaders(mail()[0]).at(-1))}}`,
  'email-auth-verdict': ({ mail }) => {
    const fake = mail().find((m) => /dmarc=fail/.test(m.headers.find((h) => h.name === 'Authentication-Results').value));
    return `SOC{${receivedIp(receivedHeaders(fake)[0])}}`;
  },
  'email-lookalike': ({ mail }) => {
    // Cyrillic letters that look like Latin ones.
    const latin = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c' };
    const domains = mail().map((m) => /@([^>]+)>/.exec(m.from)[1]).filter((d) => d.startsWith('xn--'));
    return `SOC{${domains.find((d) => [...punycodeToUnicode(d)].map((ch) => latin[ch] ?? ch).join('') === 'larkfield.example')}}`;
  },
  'email-hidden-link': ({ mail }) => {
    const host = hrefs(mail()[0].html).map((u) => new URL(u).hostname).find((h) => !h.endsWith('larkfield.example'));
    return `SOC{${registered(host)}}`;
  },
  'email-attachment-html': ({ tab, decodeBase64 }) => {
    const page = text(tab(0).mail()[0].attachments[0].bytes);
    const endpoint = decodeBase64(/endpoint: "([^"]+)"/.exec(page)[1]);
    return `SOC{${registered(new URL(endpoint).hostname)}}`;
  },
  'email-hash-lookup': ({ mail, sha256 }) => {
    const [intel, ...reported] = mail();
    const known = new Map(intel.text.split('\n').map((line) => line.split(/\s+/)).filter((parts) => parts[0]?.length === 64));
    const hit = reported.flatMap((m) => m.attachments).find((a) => known.has(sha256(a.bytes)));
    return `SOC{${known.get(sha256(hit.bytes))}_${hit.filename}}`;
  },
  'email-campaign': ({ mail }) => {
    const deliveredBy = mail().map((m) => receivedIp(receivedHeaders(m)[0]));
    return `SOC{${deliveredBy.filter((ip) => ip === deliveredBy[0]).length}_${deliveredBy[0]}}`;
  },

  // File forensics
  'forensics-mismatch': ({ sh }) => `SOC{${sh('file DCIM/*.jpg | grep -v JPEG').split(':')[0].split('/').pop()}}`,
  'forensics-author': ({ sh }) => `SOC{${sh('exiftool board-paper-leaked.pdf | grep Author').split(': ')[1].trim()}}`,
  'forensics-integrity': ({ sh }) => `SOC{${sh('sha256sum -c MANIFEST.sha256 2>/dev/null | grep FAILED').split(':')[0]}}`,
  'forensics-known-bad': ({ sh }) => {
    const line = sh('cut -d" " -f1 /intel/campaign.sha256 > bad.txt; sha256sum Downloads/* | grep -f bad.txt').trim();
    return `SOC{${line.split('/').pop()}}`;
  },
  'forensics-png-comment': ({ sh, decodeBase64 }) => {
    const b64 = sh('exiftool screenshot.png | grep Comment').split(':').slice(1).join(':').trim();
    return /SOC\{[^}]+\}/.exec(decodeBase64(b64))[0];
  },
  'forensics-timeline': ({ sh }) => {
    const listing = sh('find /srv/www -type f -newermt "2026-03-13 02:41" ! -newermt "2026-03-13 03:00" | xargs ls -lt --full-time').trim().split('\n');
    return `SOC{${listing.at(-1).split(' ').pop()}}`;
  },
  'forensics-carve': ({ sh }) => {
    const offsets = sh('binwalk card.img').split('\n').filter((l) => /^\d/.test(l)).map((l) => [Number(l.split(/\s+/)[0]), l]);
    const start = offsets.findIndex(([, l]) => l.includes('PDF'));
    const [from, to] = [offsets[start][0], offsets[start + 1][0]];
    const hash = sh(`dd if=card.img of=doc.pdf bs=1 skip=${from} count=${to - from} 2>/dev/null; sha256sum doc.pdf`);
    return `SOC{${hash.slice(0, 12)}}`;
  },

  // Network traffic analysis
  'net-ftp-creds': ({ packets }) => `SOC{${packets('ftp').map((p) => p.payload).find((s) => s.startsWith('PASS')).slice(5).trim()}}`,
  'net-scan': ({ packets }) => {
    const open = packets('ip.src == 10.0.3.15 && tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.dst == 10.0.5.87').map((p) => p.sport);
    return `SOC{${[...new Set(open)].sort((a, b) => a - b).join('_')}}`;
  },
  'net-download': ({ packets }) => {
    const streams = packets('http');
    const bad = streams.findIndex((p) => /\r\n\r\nMZ/.test(p.payload ?? ''));
    const request = streams.slice(0, bad).reverse().find((p) => p.http?.uri);
    return `SOC{${request.http.uri}}`;
  },
  'net-dns-tunnel': ({ packets }) => {
    const names = packets('dns.qry.name contains cdn-telemetry && dns.flags.response == 0').map((p) => p.dns.qname.split('.'));
    const hex = names.sort((a, b) => Number(a[0]) - Number(b[0])).map((labels) => labels[1]).join('');
    return /SOC\{[^}]+\}/.exec(Buffer.from(hex, 'hex').toString())[0];
  },
  'net-smtp': ({ packets }) => {
    const rcpt = packets('smtp').map((p) => p.payload);
    const i = rcpt.findIndex((s) => s.includes('customers'));
    return `SOC{${/RCPT TO:<([^>]+)>/.exec(rcpt.slice(0, i).reverse().find((s) => s.startsWith('RCPT')))[1]}}`;
  },
  'net-beacon': ({ packets }) => {
    const starts = packets('ip.dst == 198.51.100.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0').map((p) => p.t);
    const gaps = starts.slice(1).map((t, i) => t - starts[i]);
    return `SOC{198.51.100.66_${Math.round(gaps.reduce((a, b) => a + b, 0) / gaps.length)}}`;
  },
  'net-exfil': ({ packets }) => {
    const out = new Map();
    for (const p of packets('frame.len > 1000 && ip.src == 10.0.0.0/8')) {
      if (p.dst.startsWith('10.') || p.dport === 443) continue;
      const key = `${p.src}_${p.dport}`;
      out.set(key, (out.get(key) ?? 0) + p.len);
    }
    return `SOC{${[...out.entries()].sort((a, b) => b[1] - a[1])[0][0]}}`;
  },

  // Secure code review
  'code-sql-sink': ({ sh }) => `SOC{${enclosingFunction(sh, sh('grep -rn "+ value +" .').trim())}}`,
  'code-secret': ({ sh }) => {
    const hit = sh('grep -rn "LKIA" .').split('\n').find((line) => line && !line.includes('EXAMPLE'));
    const [path, line] = hit.replace(/^\.\//, '').split(':');
    return `SOC{${path}:${line}}`;
  },
  'code-idor': ({ sh }) => {
    const handlers = sh('cat *.py').split(/\n(?=@bp\.)/).filter((block) => /def \w+\(\w+_id\)/.test(block));
    const open = handlers.find((block) => !/owns\(|_for\(/.test(block));
    return `SOC{${/def (\w+)/.exec(open)[1]}}`;
  },
  'code-command': ({ sh }) => `SOC{${enclosingFunction(sh, sh('grep -rn "shell=True" .').trim())}}`,
  'code-path': ({ sh }) => `SOC{${enclosingFunction(sh, sh('grep -rn \'replace("../"\' .').trim())}}`,
  'code-fix': ({ sh }) => {
    const names = sh('ls patches').trim().split(/\s+/);
    const good = names.filter((name) => {
      const patch = sh(`cat patches/${name}`);
      return patch.includes('SORTS.get') && /^\+.*user_id = \?/m.test(patch);
    });
    return `SOC{${good[0]}}`;
  },

  // CVE case studies
  'cve-kev-exposed': ({ sh }) => {
    const line = sh('cut -d, -f1 kev.csv | tail -n +2 > ids.txt; grep -f ids.txt scan.csv | grep ",yes,"').trim().split('\n')[0];
    return `SOC{${line.split(',')[0]}}`;
  },
  'cve-top-product': ({ sh }) => {
    const kevIds = new Set(sh('cut -d, -f1 kev.csv | tail -n +2').trim().split('\n'));
    const counts = new Map();
    for (const line of sh('cat scan.csv').trim().split('\n').slice(1)) {
      const [host, , , cve] = line.split(',');
      if (!kevIds.has(cve)) continue;
      counts.set(cve, (counts.get(cve) ?? new Set()).add(host));
    }
    return `SOC{${[...counts.entries()].sort((a, b) => b[1].size - a[1].size)[0][0]}}`;
  },
  'cve-callback': ({ query }) => {
    const row = query('index=firewall action=allowed NOT dest_ip=10.0.3.15 NOT dest_port=443 | stats count by src_host | sort -count | head 1')[0];
    return `SOC{${row.src_host}}`;
  },
  'cve-patient-zero': ({ query }) => {
    const row = query('index=firewall dest_port=445 | stats dc(dest_host) as targets by src_host | sort -targets | head 1')[0];
    return `SOC{${row.src_host}}`;
  },
  'cve-identify': ({ sh }) => `SOC{${sh('grep -i moveit kev.csv').trim().split(',')[0]}}`,
  'cve-first-seen': ({ query }) => `SOC{${hms(query('index=ids cve=CVE-2021-26855 | stats earliest(_time) as first')[0].first)}}`,
  'cve-double-exposed': ({ tab }) => {
    // Scan tab: internet facing hosts whose CVE is on KEV.
    const kevIds = tab(0).sh('cut -d, -f1 kev.csv | tail -n +2').trim().split('\n');
    const exposed = new Map(tab(0).sh('grep ",yes," scan.csv').trim().split('\n')
      .map((l) => l.split(','))
      .filter((cols) => kevIds.includes(cols[3]))
      .map((cols) => [cols[0], cols[3]]));
    // IDS tab: which KEV CVE is being attacked against which host.
    const attacked = tab(1).query('index=ids action=detected | stats values(cve) as cves by dest_host');
    for (const row of attacked) {
      const cves = [].concat(row.cves);
      if (exposed.has(row.dest_host) && cves.includes(exposed.get(row.dest_host))) return `SOC{${row.dest_host}}`;
    }
    return 'SOC{unknown}';
  },

  // Incident response capstone
  'capstone-phish': ({ mail }) => {
    const host = hrefs(mail()[0].html).map((u) => new URL(u).hostname).find((h) => !h.endsWith('larkfield.example'));
    return `SOC{${registered(host)}}`;
  },
  'capstone-access': ({ query }) => `SOC{${query('index=windows EventCode=4624 user=m.garcia NOT src_ip=10.*')[0].src_ip}}`,
  'capstone-beacon': ({ packets }) => {
    const starts = packets('ip.addr == 198.51.100.202 && tcp.flags.syn == 1 && tcp.flags.ack == 0').map((p) => p.t);
    const gaps = starts.slice(1).map((t, i) => t - starts[i]);
    return `SOC{198.51.100.202_${Math.round(gaps.reduce((a, b) => a + b, 0) / gaps.length)}}`;
  },
  'capstone-stage': ({ sh }) => `SOC{${sh('find /share -type f -newermt "2026-03-13 10:00"').trim().split('\n')[0]}}`,
  'capstone-exfil': ({ packets }) => {
    const out = new Map();
    for (const p of packets('frame.len > 1000 && ip.src == 10.0.0.0/8')) {
      if (p.dst.startsWith('10.') || p.dport === 443) continue;
      const key = `${p.dst}_${p.dport}`;
      out.set(key, (out.get(key) ?? 0) + p.len);
    }
    return `SOC{${[...out.entries()].sort((a, b) => b[1] - a[1])[0][0]}}`;
  },
  'capstone-timeline': ({ tab }) => {
    const account = /@/.test(tab(0).mail()[0].to) ? tab(0).mail()[0].to.split('@')[0] : tab(0).mail()[0].to;
    const host = tab(1).query('index=windows EventCode=4688 user=m.garcia')[0].host;
    const c2 = tab(2).packets('').filter((p) => !p.dst.startsWith('10.') && !p.dst.startsWith('192.0.2'))[0].dst;
    return `SOC{${account}_${host}_${c2}}`;
  }
};

// Given a grep -rn hit like "./file.py:12:...", the name of the function that
// line sits in.
function enclosingFunction(sh, hit) {
  const [file, line] = hit.split(':');
  const lines = sh(`cat ${file}`).split('\n').slice(0, Number(line));
  return /def (\w+)/.exec(lines.reverse().find((l) => l.startsWith('def ')))[1];
}
