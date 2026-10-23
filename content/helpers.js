// Helpers shared by the content files.

// True if the learner ran `name` successfully and the arguments pass `test`.
export function ran(log, name, test = () => true) {
  return log.some((event) => event.type === 'command' && event.name === name && event.exit === 0 && test(event.args.join(' '), event));
}

// Seeded random numbers so generated logs are identical on every visit.
export function random(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (min, max) => min + Math.floor(next() * (max - min + 1)),
    pick: (list) => list[Math.floor(next() * list.length)],
    shuffle: (list) => {
      const copy = [...list];
      for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
      }
      return copy;
    }
  };
}

export function pad2(n) {
  return String(n).padStart(2, '0');
}

// A timestamp in common log format, counting seconds from a fixed start.
export function clf(offsetSeconds, start = Date.UTC(2026, 2, 13, 6, 0, 0)) {
  const d = new Date(start + offsetSeconds * 1000);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${pad2(d.getUTCDate())}/${months[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} +0000`;
}

export function iso(offsetSeconds, start = Date.UTC(2026, 2, 13, 6, 0, 0)) {
  return new Date(start + offsetSeconds * 1000).toISOString().replace('.000Z', 'Z');
}

// ------------------------------------------------------------ SIEM events
// Every generated event has _time (milliseconds), index, sourcetype, the
// parsed fields, and _raw, the line as the original system wrote it.

export const DAY = Date.UTC(2026, 2, 13);

// Milliseconds for a time of day on the lab date, 13 March 2026 (UTC).
export function at(hours, minutes = 0, seconds = 0, base = DAY) {
  return base + ((hours * 60 + minutes) * 60 + seconds) * 1000;
}

export function hms(ms) {
  return new Date(ms).toISOString().slice(11, 19);
}

function syslogStamp(ms) {
  const d = new Date(ms);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${months[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${hms(ms)}`;
}

// An sshd line from a Linux auth log.
export function sshEvent(time, { host = 'web01', action, user, ip, port = 40000, method = 'password', invalid = false, pid = 2200 }) {
  const raw = action === 'success'
    ? `${syslogStamp(time)} ${host} sshd[${pid}]: Accepted ${method} for ${user} from ${ip} port ${port} ssh2`
    : `${syslogStamp(time)} ${host} sshd[${pid}]: Failed ${method} for ${invalid ? 'invalid user ' : ''}${user} from ${ip} port ${port} ssh2`;
  return { _time: time, index: 'linux', sourcetype: 'linux_secure', host, process: 'sshd', action, user, src_ip: ip, src_port: port, auth_method: method, ...(invalid ? { user_exists: 'false' } : {}), _raw: raw };
}

// A web server access log line in the combined format.
export function webEvent(time, { host = 'www01', ip, method = 'GET', uri, status = 200, bytes = 1200, ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36', referer = '-' }) {
  return {
    _time: time, index: 'web', sourcetype: 'access_combined', host, src_ip: ip, method, uri, status, bytes, useragent: ua,
    _raw: `${ip} - - [${clf(0, time)}] "${method} ${uri} HTTP/1.1" ${status} ${bytes} "${referer}" "${ua}"`
  };
}

const WINDOWS_EVENTS = {
  1102: 'The audit log was cleared',
  4624: 'An account was successfully logged on',
  4625: 'An account failed to log on',
  4634: 'An account was logged off',
  4672: 'Special privileges assigned to new logon',
  4688: 'A new process has been created',
  4720: 'A user account was created',
  4722: 'A user account was enabled',
  4724: 'An attempt was made to reset an account password',
  4728: 'A member was added to a security-enabled global group',
  4732: 'A member was added to a security-enabled local group',
  4740: 'A user account was locked out',
  4768: 'A Kerberos authentication ticket (TGT) was requested',
  4776: 'The computer attempted to validate the credentials for an account',
  7045: 'A service was installed in the system'
};

// A Windows Security (or System) event, flattened the way most SIEMs show it.
export function winEvent(time, code, fields = {}) {
  const log = code === 7045 ? 'System' : 'Security';
  const pairs = Object.entries(fields).map(([k, v]) => `${k}=${/\s/.test(String(v)) ? `"${v}"` : v}`).join(' ');
  return {
    _time: time, index: 'windows', sourcetype: `WinEventLog:${log}`, EventCode: code, message: WINDOWS_EVENTS[code] ?? '', ...fields,
    _raw: `${new Date(time).toISOString().replace('.000', '')} LogName=${log} EventCode=${code} Message="${WINDOWS_EVENTS[code] ?? ''}" ${pairs}`
  };
}

// A web proxy log line: who asked for what, and how much went each way.
export function proxyEvent(time, { ip, host, user, dest, path = '/', method = 'GET', status = 200, bytesOut = 400, bytesIn = 2000, ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/124.0', category = 'business' }) {
  return {
    _time: time, index: 'proxy', sourcetype: 'proxy', src_ip: ip, src_host: host, user, dest_host: dest, url: `http://${dest}${path}`, method, status, bytes_out: bytesOut, bytes_in: bytesIn, useragent: ua, category,
    _raw: `${new Date(time).toISOString().replace('.000', '')} ${ip} ${user} ${method} http://${dest}${path} ${status} out=${bytesOut} in=${bytesIn} cat=${category} "${ua}"`
  };
}

// True if the learner ran a SIEM search that passes `test`.
export function queried(log, test = () => true) {
  return log.some((event) => event.type === 'query' && test(event.query.toLowerCase(), event));
}
