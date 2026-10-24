import { ran, random } from './helpers.js';
import { utf8, concat, toBase64 } from '../assets/js/lib/bytes.js';
import { crc32, sha256 } from '../assets/js/lib/hash.js';

// Small but structurally honest files: real signatures, real PNG chunks with
// correct checksums, real PDF info dictionaries. Nothing here is ever shown
// as a picture; the files only exist to be examined.

const at = (d, h, m = 0, s = 0) => Date.UTC(2026, 2, d, h, m, s);

function noise(seed, length, { text = false } = {}) {
  const r = random(seed);
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) bytes[i] = text ? r.int(97, 122) : r.int(0, 255);
  return bytes;
}

function u32(n) {
  return Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
}

function chunk(type, data) {
  const body = concat(utf8(type), data);
  return concat(u32(data.length), body, u32(crc32(body) >>> 0));
}

export function png({ width = 640, height = 480, text = [], seed = 1, size = 600 }) {
  return concat(
    Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
    chunk('IHDR', concat(u32(width), u32(height), Uint8Array.of(8, 6, 0, 0, 0))),
    ...text.map(([key, value]) => chunk('tEXt', concat(utf8(key), Uint8Array.of(0), utf8(value)))),
    chunk('IDAT', noise(seed, size)),
    chunk('IEND', new Uint8Array(0))
  );
}

export function jpeg(seed, size = 900) {
  return concat(Uint8Array.of(0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10), utf8('JFIF\0'), Uint8Array.of(1, 1, 0, 0, 1, 0, 1, 0, 0), noise(seed, size), Uint8Array.of(0xff, 0xd9));
}

export function pdf(info, body = 'BT /F1 12 Tf 72 720 Td (Page 1) Tj ET') {
  const fields = Object.entries(info).map(([k, v]) => `/${k} (${v})`).join(' ');
  return utf8(`%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [4 0 R] /Count 1 >> endobj\n3 0 obj << ${fields} >> endobj\n4 0 obj << /Type /Page /Parent 2 0 R /Contents 5 0 R >> endobj\n5 0 obj << /Length ${body.length} >> stream\n${body}\nendstream endobj\ntrailer << /Root 1 0 R /Info 3 0 R >>\n%%EOF\n`);
}

export function zip(name, content) {
  const data = utf8(content);
  const header = concat(Uint8Array.of(0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0), u32(crc32(data) >>> 0).reverse(), u32(data.length).reverse(), u32(data.length).reverse(), Uint8Array.of(name.length, 0, 0, 0), utf8(name));
  const end = concat(Uint8Array.of(0x50, 0x4b, 0x05, 0x06), new Uint8Array(18));
  return concat(header, data, end);
}

export function elf(seed, size = 1200) {
  return concat(Uint8Array.of(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0), noise(seed, size));
}

export function exe(seed, size = 1500) {
  const bytes = noise(seed, size);
  bytes.set(utf8('MZ'), 0);
  bytes.set(utf8('This program cannot be run in DOS mode.'), 78);
  return bytes;
}

// The shared case folder for the lessons.
function caseFiles() {
  const photoWithZip = concat(jpeg(31, 1400), zip('passwords.txt', 'vpn: Spring2026!\nwifi: larkfield-guest-77\n'));
  const files = {
    '/cases/031/': { owner: 'learner' },
    '/cases/031/README.txt': 'Case 031. Laptop seized from a contractor on 13 March 2026.\nWork on the copies in this folder. The originals are in the evidence store.\n',
    '/cases/031/downloads/invoice_0313.pdf': pdf({ Title: 'Invoice 0313', Author: 'Office Supplies Ltd', Creator: 'Larkfield Docs 4.2', Producer: 'PDF Engine 9.1', CreationDate: 'D:20260312101500Z' }),
    '/cases/031/downloads/holiday-photo.jpg': photoWithZip,
    '/cases/031/downloads/quarterly.xlsx': zip('xl/workbook.xml', '<workbook/>'),
    '/cases/031/downloads/readme.txt': elf(5),
    '/cases/031/downloads/scan.pdf': exe(6),
    '/cases/031/downloads/notes.txt': 'call the client back about the invoice\nchange vpn password\n',
    '/cases/031/docs/proposal.pdf': pdf({ Title: 'Larkfield expansion proposal', Author: 'Jordan Hale', Creator: 'Microsoft Word for Microsoft 365', Producer: 'Microsoft Word for Microsoft 365', CreationDate: 'D:20260209143012Z', ModDate: 'D:20260312231544Z' }),
    '/cases/031/docs/logo.png': png({ width: 512, height: 512, seed: 9, text: [['Software', 'Snipping Tool 11.2309'], ['Author', 'JHALE-LAPTOP\\jordan'], ['Comment', 'draft for Q2 deck']] }),
    '/cases/031/intel/known-bad.sha256': ''
  };
  files['/cases/031/intel/known-bad.sha256'] = [
    `${sha256(noise(901, 64))}  dropper.exe`,
    `${sha256(files['/cases/031/downloads/scan.pdf'])}  invoice_scan.exe`,
    `${sha256(noise(902, 64))}  loader.dll`
  ].join('\n') + '\n';
  // Web root with a timeline to reconstruct.
  const web = {
    'index.php': [at(2, 9), '<?php include "header.php"; ?>\n'], 'header.php': [at(2, 9), '<header>Larkfield</header>\n'], 'contact.php': [at(2, 9), '<form></form>\n'],
    'robots.txt': [at(1, 12), 'User-agent: *\n'], 'uploads/avatar_12.png': [at(10, 15, 22), png({ seed: 12 })], 'uploads/avatar_31.png': [at(12, 11, 3), png({ seed: 31 })],
    'uploads/avatar_77.php': [at(13, 2, 43, 51), '<?php /* uploaded file that should never run as code */ ?>\n'],
    '.htaccess': [at(13, 2, 45, 7), 'AddType application/x-httpd-php .png\n']
  };
  for (const [name, [mtime, content]] of Object.entries(web)) files[`/cases/031/webroot/${name}`] = { content, mtime };
  // A manifest written when the evidence was copied.
  const manifestNames = ['downloads/invoice_0313.pdf', 'downloads/notes.txt', 'docs/proposal.pdf', 'docs/logo.png'];
  files['/cases/031/MANIFEST.sha256'] = manifestNames.map((n) => `${sha256(files[`/cases/031/${n}`])}  ${n}`).join('\n') + '\n';
  return files;
}

function lessonMachine(motd) {
  return { type: 'shell', motd, cwd: '/cases/031', files: caseFiles(), hostname: 'forensics' };
}

export default {
  id: 'forensics',
  title: 'File forensics',
  short: 'Forensics',
  summary: 'Identify files by their contents, hash them and compare against known lists, read metadata, build timelines, carve hidden data, and handle evidence so it holds up.',
  intro: 'When a device is part of an incident, the files on it are evidence. This topic covers the questions a forensic analyst asks of every file: what is it really, have we seen it before, who made it and when, is anything hidden inside it, and can we prove it has not changed since we collected it.',
  outcomes: [
    'Identify a file from its signature and spot disguised files in bulk',
    'Hash files and check them against known good and known bad lists',
    'Read PDF and image metadata and judge how far to trust it',
    'Build a timeline from file modification times',
    'Find and carve files hidden inside other files',
    'Verify evidence integrity with a hash manifest'
  ],
  lessons: [
    {
      id: 'forensics-signatures',
      title: 'What a file really is',
      summary: 'Signatures, containers, and checking a whole folder for files that lie about their type.',
      minutes: 11,
      terms: [
        ['file signature', 'A fixed sequence of bytes at the start of a file that identifies its format, also called magic bytes. `%PDF` for PDF, `PK` for ZIP, `MZ` for Windows programs.'],
        ['container format', 'A format that holds other files. Word, Excel and PowerPoint documents, Java archives and Android apps are all ZIP files inside.'],
        ['extension mismatch', 'A file whose name says one type and whose contents say another. Sometimes harmless, often an attempt to hide something.'],
        ['triage', 'A quick first pass to decide which files deserve a closer look. With thousands of files, you cannot examine every one by hand.']
      ],
      workspace: lessonMachine('Case 031 workstation. Start with: ls -R\n'),
      blocks: [
        { type: 'text', body: 'The Linux topic showed that a file\'s name is just a label and its first bytes reveal its real type. Forensic work uses that at scale. A seized laptop has hundreds of thousands of files, and the ones that lie about what they are deserve attention first.' },
        { type: 'example', title: 'Checking a folder at once', steps: [
          { cmd: 'ls downloads', note: 'Names and extensions only.' },
          { cmd: 'file downloads/*', note: '`file` reads the first bytes of each one and reports what it finds.' },
          { cmd: 'xxd downloads/scan.pdf | head -n 2', note: 'Confirm by eye. The first two bytes, `4d 5a`, are MZ.' }
        ] },
        { type: 'task', text: 'Run `file` on everything in `downloads` and compare each result with the extension.', check: (log) => ran(log, 'file', (a) => a.includes('downloads')) },
        { type: 'table', head: ['Name', 'Says it is', 'Really is', 'Concern'], rows: [['`invoice_0313.pdf`', 'PDF', 'PDF', 'None'], ['`holiday-photo.jpg`', 'JPEG', 'JPEG', 'Looks fine, but see the carving lesson'], ['`quarterly.xlsx`', 'Excel', 'ZIP', 'None. Office files are ZIP containers'], ['`readme.txt`', 'Text', 'Linux program', 'High'], ['`scan.pdf`', 'PDF', 'Windows program', 'High']] },
        { type: 'quiz', question: '`file` reports `quarterly.xlsx` as a ZIP archive. Should you flag it?', options: [
          { text: 'No. Modern Office documents are ZIP files containing XML', correct: true, why: '.docx, .xlsx and .pptx are all ZIP containers, as are .jar and .apk. A mismatch check has to know about containers or it will drown you in false alarms.' },
          { text: 'Yes. A spreadsheet should never be a ZIP', why: 'Since Office 2007 they always are.' },
          { text: 'Yes. ZIP files are always suspicious', why: 'ZIP is everywhere. It is the contents that matter.' }
        ] },
        { type: 'text', body: 'With hundreds of files, you want only the mismatches. Combining `file` with `grep` does that: list everything, then keep the lines where a name ending in a document or picture extension is described as a program.' },
        { type: 'task', text: 'Print only the lines from `file downloads/*` that mention "executable".', hint: '`file downloads/* | grep executable`', check: (log) => ran(log, 'grep', (a) => /execut/i.test(a)) },
        { type: 'predict', question: 'A file called `report.pdf` starts with `25 50 44 46` (%PDF) but `file` also finds a ZIP signature further inside. What could that mean?', options: [
          { text: 'Something has been appended or embedded inside a real PDF', correct: true, why: 'Files can be stacked. Many readers ignore trailing data, so a valid PDF can carry another file inside it. The carving lesson covers how to find and extract it.' },
          { text: 'The PDF is corrupt', why: 'It may open perfectly well. Readers stop at the end of the PDF structure.' },
          { text: 'It is really a ZIP and the PDF header is fake', why: 'The PDF header comes first and the file is a valid PDF. The ZIP is the extra part.' }
        ] },
        { type: 'note', title: 'Tools at scale', body: 'Forensic suites do this across whole disks, flagging signature mismatches automatically. The logic is the same as `file | grep`: compare what the name says with what the bytes say.' }
      ]
    },
    {
      id: 'forensics-hashing',
      title: 'Hashes and known files',
      summary: 'What a hash proves, MD5 and SHA-256, and filtering evidence with known good and known bad hash sets.',
      minutes: 12,
      terms: [
        ['hash function', 'A calculation that turns any amount of data into a short, fixed length fingerprint. The same input always gives the same hash, and any change gives a completely different one.'],
        ['collision', 'Two different inputs with the same hash. Practical collisions exist for MD5 and SHA-1, so they should not be trusted where someone might have forged a file.'],
        ['known good set', 'Hashes of standard files, such as operating system and common software files. Matching them lets you skip thousands of files that cannot be interesting. NIST\'s NSRL is the best known.'],
        ['known bad set', 'Hashes of files already identified as malicious, from threat intelligence or earlier cases.']
      ],
      workspace: lessonMachine('Case 031 workstation. Try: sha256sum downloads/*\n'),
      blocks: [
        { type: 'text', body: 'A **hash** is a fingerprint of a file\'s exact bytes. Two files with the same SHA-256 are, for all practical purposes, identical. Change a single bit and the hash changes completely. That makes hashes useful for two different jobs: recognising files, and proving files have not changed.' },
        { type: 'example', steps: [
          { cmd: 'sha256sum downloads/notes.txt', note: 'The 64 hex characters are the SHA-256 of the file.' },
          { cmd: 'md5sum downloads/notes.txt', note: 'MD5 is shorter and older. You will still see it in older tools and reports.' },
          { cmd: 'sha256sum downloads/*', note: 'Hash every file at once.' }
        ] },
        { type: 'table', head: ['Algorithm', 'Length', 'Use it for'], rows: [['MD5', '32 hex characters', 'Looking things up in older databases. Not for proving integrity'], ['SHA-1', '40 hex characters', 'The same. Collisions have been demonstrated'], ['SHA-256', '64 hex characters', 'Everything. The current standard for evidence']] },
        { type: 'text', body: 'On a real disk, most files are standard operating system and software files. Removing everything that matches a **known good** set shrinks the pile dramatically. Then matching against a **known bad** set flags files already known to be malicious. The case folder has a short known bad list in `intel/known-bad.sha256`.' },
        { type: 'task', text: 'Read `intel/known-bad.sha256`, then hash everything in `downloads` and see whether any hash appears on the list.', hint: '`cat intel/known-bad.sha256`, then `sha256sum downloads/*`.', check: (log) => ran(log, 'sha256sum', (a) => a.includes('downloads')) },
        { type: 'text', body: 'Comparing by eye works for three hashes. For thousands, let grep do it. `grep -f` reads its patterns from a file, one per line, so you can search for every known bad hash at once.' },
        { type: 'example', title: 'Matching a whole list', steps: [
          { cmd: 'cut -d" " -f1 intel/known-bad.sha256 > bad.txt', note: 'Keep just the hash column.' },
          { cmd: 'sha256sum downloads/* | grep -f bad.txt', note: 'Every line of our hashes that contains any hash from the list.' }
        ] },
        { type: 'task', text: 'Use `grep -f` to find which file in `downloads` is on the known bad list.', check: (log) => ran(log, 'grep', (a) => a.includes('-f')) },
        { type: 'quiz', question: 'The list calls the bad file `invoice_scan.exe`. On this laptop it is called `scan.pdf`. What does that tell you?', options: [
          { text: 'Names are easy to change, so match on hashes, never on names', correct: true, why: 'The bytes are identical, so it is the same file renamed. A search by name would have missed it completely.' },
          { text: 'It is probably a different file that happens to share a hash', why: 'An accidental SHA-256 match is so unlikely that you can rule it out.' },
          { text: 'The list is wrong', why: 'The list records the name the file had when someone else found it. Names change, hashes do not.' }
        ] },
        { type: 'note', title: 'Hashes find copies, not relatives', body: 'Malware authors often change a few bytes per victim so each copy has a new hash. Similarity hashes such as ssdeep and TLSH help find files that are close but not identical. A known bad hash match is strong evidence; no match proves very little.' }
      ]
    },
    {
      id: 'forensics-metadata',
      title: 'Metadata',
      summary: 'What documents and images record about themselves, how to read it, and how far to trust it.',
      minutes: 11,
      terms: [
        ['metadata', 'Data about data: author, software, creation time, device, location. Stored inside the file alongside its content.'],
        ['PDF info dictionary', 'The part of a PDF that holds Title, Author, Creator (the app used to write it), Producer (the app that made the PDF) and dates.'],
        ['PNG text chunk', 'A named piece of text stored inside a PNG image, such as Software, Author or Comment.'],
        ['anti-forensics', 'Deliberately removing or faking evidence, such as wiping metadata or changing timestamps.']
      ],
      workspace: lessonMachine('Case 031 workstation. Try: exiftool docs/proposal.pdf\n'),
      blocks: [
        { type: 'text', body: 'Files often remember more about themselves than their authors realise. A PDF can record who wrote it and with which program. A screenshot can record the computer and user name that took it. This is **metadata**, and it has broken plenty of real cases open.' },
        { type: 'example', steps: [
          { cmd: 'exiftool docs/proposal.pdf', note: 'Reads the PDF info dictionary: title, author, the software and the dates.' },
          { cmd: 'exiftool docs/logo.png', note: 'PNG images can carry text chunks with the software and author.' },
          { cmd: 'strings docs/proposal.pdf | grep Author', note: 'Metadata is just bytes in the file, so strings finds it too.' }
        ] },
        { type: 'task', text: 'Read the metadata of `docs/proposal.pdf`.', check: (log) => ran(log, 'exiftool', (a) => a.includes('proposal')) },
        { type: 'answer', question: 'According to its metadata, who is the author of `proposal.pdf`?', accept: ['Jordan Hale', 'jordan hale'], hint: 'Look at the Author line from exiftool.', explain: 'The Creator line also tells you it was written in Word, and the Modify Date shows it was last changed late on 12 March, the night before the laptop was seized.' },
        { type: 'task', text: 'Now read the metadata of `docs/logo.png`. What does the Author field reveal?', check: (log) => ran(log, 'exiftool', (a) => a.includes('logo')) },
        { type: 'text', body: 'The PNG says it was made with the Snipping Tool by `JHALE-LAPTOP\\jordan`. That is a computer name and a Windows user name. Details like these connect a file to a specific machine, which can matter more than the person named in a document.' },
        { type: 'quiz', question: 'A leaked PDF has Author: "Helen Ward". Is that enough to say Helen leaked it?', options: [
          { text: 'No. Author is often whoever first created the template, and it can be edited by anyone', correct: true, why: 'Metadata is a lead, not proof. Word fills Author from the account that created the file, documents get copied and reused, and anyone can change these fields in seconds. Corroborate it with other evidence such as access logs.' },
          { text: 'Yes. Metadata cannot be changed', why: 'It can, with ordinary software, in seconds.' },
          { text: 'Yes, if the creation date matches her working hours', why: 'That is still only consistent with her, not proof. Look for evidence from systems she cannot edit, like server logs.' }
        ] },
        { type: 'note', title: 'The other side', body: 'Organisations should strip metadata from documents before publishing them. Internal user names, server paths and software versions in public files help attackers plan phishing and target vulnerable software.' }
      ]
    },
    {
      id: 'forensics-timeline',
      title: 'File timelines',
      summary: 'Modification times, sorting files by when they changed, and finding everything changed in an incident window.',
      minutes: 13,
      terms: [
        ['mtime', 'Modification time: when a file\'s contents last changed. Shown by `ls -l` and `stat`.'],
        ['MAC times', 'Modified, accessed and changed (metadata change) times. Many filesystems also keep a creation or birth time. Together they help show what happened to a file.'],
        ['timestomping', 'Changing a file\'s timestamps to make it blend in, for example setting a web shell\'s time to match the files around it.'],
        ['incident window', 'The period when you believe the attacker was active, usually taken from logs. You search for file changes inside it.']
      ],
      workspace: lessonMachine('Case 031 workstation. Try: ls -lt --full-time webroot\n'),
      blocks: [
        { type: 'text', body: 'Every file records when its contents last changed: its **mtime**. On a web server that is rarely updated, a handful of files changed in the middle of the night stand out immediately. Combined with log times, file times let you reconstruct what an attacker did.' },
        { type: 'example', steps: [
          { cmd: 'ls -lt webroot', note: '`-t` sorts newest first. The default time format hides seconds.' },
          { cmd: 'ls -lt --full-time webroot webroot/uploads', note: '`--full-time` shows the exact time, which you need to line files up with logs.' },
          { cmd: 'stat webroot/.htaccess', note: '`stat` shows the details for a single file.' }
        ] },
        { type: 'task', text: 'List the web root and its uploads folder sorted by time, with full timestamps.', hint: '`ls -lat --full-time webroot webroot/uploads`', check: (log) => ran(log, 'ls', (a) => a.includes('--full-time')) },
        { type: 'text', body: 'The web server logs for this case show the attacker\'s first request at 02:41 UTC on 13 March. `find` can list every file changed after a given moment, which is exactly the question you want answered.' },
        { type: 'example', title: 'Searching an incident window', steps: [
          { cmd: 'find webroot -type f -newermt "2026-03-13 02:40"', note: 'Files modified after 02:40 UTC on 13 March.' },
          { cmd: 'touch -d "2026-03-13 02:40" /tmp/start', note: 'Another way: make a reference file with that exact time...' },
          { cmd: 'find webroot -type f -newer /tmp/start', note: '...and ask for files newer than it. Older find versions only support this form.' }
        ] },
        { type: 'task', text: 'Find every file in `webroot` modified after 02:40 UTC on 13 March 2026.', check: (log) => log.some((e) => e.name === 'find' && /-newer/.test(e.args.join(' ')) && e.exit === 0) },
        { type: 'order', question: 'Put what happened on the web server in order, using the file times.', items: ['`avatar_31.png` uploaded by a real user (12 March)', '`avatar_77.php` uploaded (02:43:51 on 13 March)', '`.htaccess` changed so .png files run as PHP (02:45:07)'], explain: 'The attacker uploaded a PHP file through the avatar form, then changed `.htaccess` so the server would run code in files with other extensions too. The order tells you how the upload filter was bypassed.' },
        { type: 'quiz', question: 'A file in the web root has an mtime from two years ago, but the logs show it being requested for the first time last night. What should you consider?', options: [
          { text: 'Its timestamp may have been changed to make it blend in', correct: true, why: 'Timestomping is common. Modification times are easy to set with `touch -d`. Other sources, such as logs, backups and filesystem metadata that is harder to change, help confirm the real history.' },
          { text: 'The logs must be wrong', why: 'Logs written by another system are usually more reliable than a timestamp the attacker could edit.' },
          { text: 'Nothing. Old files are safe', why: 'Age on disk says nothing about safety, and here it contradicts other evidence.' }
        ] },
        { type: 'note', title: 'Convert, then compare', body: 'Filesystem times are usually stored in UTC and shown in local time by many tools. Make sure file times and log times are in the same zone before you line them up, or a one hour daylight saving shift will put events in the wrong order.' }
      ]
    },
    {
      id: 'forensics-carving',
      title: 'Hidden and embedded data',
      summary: 'Files inside files, scanning for signatures at every offset, and carving data out with dd.',
      minutes: 13,
      terms: [
        ['carving', 'Extracting a file from a larger blob of data by its signatures and structure, without relying on a filesystem to say where it is.'],
        ['offset', 'A position in a file, counted in bytes from the start. Offset 0 is the first byte.'],
        ['appended data', 'Bytes added after the logical end of a file. Most programs stop reading at the end marker and never notice it.'],
        ['binwalk', 'A tool that scans a file for known signatures at every offset and lists what it finds and where.']
      ],
      workspace: lessonMachine('Case 031 workstation. Try: binwalk downloads/holiday-photo.jpg\n'),
      blocks: [
        { type: 'text', body: 'Most file formats have a clear end. A JPEG finishes with the bytes `FF D9`, a PNG with an `IEND` chunk, a PDF with `%%EOF`. Image viewers stop reading there, so anything appended afterwards is invisible in normal use but still sitting on disk.' },
        { type: 'task', text: 'Scan `downloads/holiday-photo.jpg` with binwalk.', check: (log) => ran(log, 'binwalk', (a) => a.includes('holiday')) },
        { type: 'text', body: 'binwalk finds two signatures: the JPEG at offset 0, as expected, and a ZIP archive further in. The photo opens normally and is also a container for something else. Now **carve** it out. `dd` copies a range of bytes; with `bs=1`, `skip` is the starting offset in bytes.' },
        { type: 'example', title: 'Carving with dd', steps: [
          { cmd: 'binwalk downloads/holiday-photo.jpg', note: 'Note the decimal offset of the ZIP.' },
          { cmd: 'dd if=downloads/holiday-photo.jpg of=/tmp/hidden.zip bs=1 skip=1422', note: 'Copy everything from that offset to the end into a new file.' },
          { cmd: 'file /tmp/hidden.zip', note: 'Check what you carved.' },
          { cmd: 'strings /tmp/hidden.zip', note: 'This archive is stored uncompressed, so its text is readable directly.' }
        ] },
        { type: 'task', text: 'Carve the ZIP out of the photo into `/tmp/hidden.zip` and look at what it contains.', hint: 'Use the offset binwalk reports as `skip`.', check: (log, ws) => {
          try {
            const bytes = ws.fs.readFile('/tmp/hidden.zip', 'learner');
            return bytes[0] === 0x50 && bytes[1] === 0x4b;
          } catch {
            return false;
          }
        } },
        { type: 'predict', question: 'You carve from the start of an embedded PDF to the end of the whole file, but another file follows the PDF. What happens when you hash what you carved?', options: [
          { text: 'You get a different hash from the original PDF, because the carved file includes the extra bytes', correct: true, why: 'Hashes are exact. To match a known file you must carve exactly its bytes: from its start to its own end marker, or to where the next file begins.' },
          { text: 'The same hash, because hashes ignore trailing data', why: 'Hashes cover every byte. Even one extra byte changes the result.' },
          { text: 'dd refuses to carve past the end of the PDF', why: 'dd knows nothing about formats. It copies the bytes you ask for.' }
        ] },
        { type: 'answer', question: 'binwalk reports a PDF at decimal offset 5120 and the next signature at 9216. What `count` gives exactly the PDF with `bs=1 skip=5120`?', accept: ['4096'], hint: 'Count is the number of bytes: next offset minus start offset.', explain: '9216 minus 5120 is 4096 bytes. `dd if=card.img of=doc.pdf bs=1 skip=5120 count=4096` carves exactly that range.' },
        { type: 'note', title: 'Where hidden data turns up', body: 'Appended archives in images, files inside documents, data in unallocated disk space after deletion, and old content in file slack (the unused end of a disk block). Carving tools such as PhotoRec and bulk_extractor work across whole disk images using the same idea.' }
      ]
    },
    {
      id: 'forensics-handling',
      title: 'Handling evidence',
      summary: 'Working on copies, hashing at collection, chain of custody, and verifying nothing changed.',
      minutes: 10,
      terms: [
        ['forensic image', 'An exact, bit for bit copy of a disk or device. Analysis is done on the copy so the original stays untouched.'],
        ['write blocker', 'Hardware or software that lets you read a disk without any chance of writing to it.'],
        ['chain of custody', 'A record of who had the evidence, when, and what they did with it, from collection to court.'],
        ['order of volatility', 'Collecting the most short lived evidence first: memory and network connections before disk, disk before backups.']
      ],
      workspace: lessonMachine('Case 031 workstation. Try: cat MANIFEST.sha256\n'),
      blocks: [
        { type: 'text', body: 'Evidence is only useful if you can show it has not changed since it was collected. Forensic practice is built around that: copy first, hash the copy, work on another copy, and record every step.' },
        { type: 'order', question: 'Put these steps of collecting a laptop disk in order.', items: ['Photograph the device and note its state', 'Attach the disk through a write blocker', 'Make a forensic image', 'Hash the original and the image and confirm they match', 'Record the hashes and the handover in the chain of custody form', 'Analyse a working copy, never the original'], explain: 'If the laptop is still running, memory comes first, because it disappears when the power goes. That is the order of volatility.' },
        { type: 'text', body: 'When this case folder was copied, someone wrote a **manifest**: the SHA-256 of each file. `sha256sum -c` reads a manifest and checks every file against it.' },
        { type: 'task', text: 'Verify the case folder against `MANIFEST.sha256`.', hint: '`sha256sum -c MANIFEST.sha256` (run it from /cases/031).', check: (log) => ran(log, 'sha256sum', (a) => a.includes('-c')) },
        { type: 'quiz', question: 'Why is SHA-256 used for evidence manifests rather than MD5?', options: [
          { text: 'MD5 collisions can be made deliberately, so a forged file could match', correct: true, why: 'For integrity against someone who might tamper with evidence, you need a hash nobody can forge a match for. MD5 and SHA-1 no longer meet that bar.' },
          { text: 'SHA-256 is faster', why: 'MD5 is actually faster. Speed is not the reason.' },
          { text: 'MD5 cannot hash large files', why: 'It can hash files of any size.' }
        ] },
        { type: 'predict', question: 'An analyst opens an evidence file in a text editor, changes nothing, and saves it. What does `sha256sum -c` say afterwards?', options: [
          { text: 'It may report FAILED, because saving can change bytes such as line endings or encoding', correct: true, why: 'Many editors normalise line endings or add a final newline on save. Even "no changes" can change the bytes. That is why you never open originals in tools that can write.' },
          { text: 'OK, because the content was not changed', why: 'Hashes see bytes, not intentions. Invisible changes still count.' },
          { text: 'It cannot check edited files', why: 'It checks any file. The hash simply will not match.' }
        ] },
        { type: 'note', title: 'Write it down', body: 'For every action, record what you did, when, with which tool and version, and the hashes before and after. If someone challenges your findings, these notes are what allow another examiner to repeat your work and get the same result.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'forensics-mismatch',
      title: 'Not a holiday snap',
      difficulty: 'easy',
      points: 100,
      skills: ['file', 'signatures', 'grep'],
      prepare: ['forensics-signatures'],
      brief: 'A USB stick found on a desk in a restricted area holds a camera folder with 48 photos. The owner says it only has holiday pictures. One of the files is not a picture at all.',
      goal: 'Find the file in `/evidence/usb/DCIM` that is not really an image and submit its file name as `SOC{name}`.',
      flag: 'iVCnsLvakPAjPxEPeLyFu7I=',
      workspace: () => {
        const r = random(48);
        const files = {};
        const numbers = r.shuffle(Array.from({ length: 48 }, (_, i) => 4401 + i * 3));
        numbers.forEach((n, i) => {
          files[`/evidence/usb/DCIM/IMG_${n}.jpg`] = i === 29 ? pdf({ Title: 'Site access codes', Author: 'facilities', Creator: 'Larkfield Docs 4.2' }, 'BT (Door 3F: 4471#) Tj ET') : jpeg(n, r.int(600, 1600));
        });
        files['/evidence/usb/DCIM/Thumbs.db'] = noise(4, 300);
        files['/evidence/usb/autorun.inf'] = '[autorun]\nlabel=HOLIDAY\n';
        return { type: 'shell', cwd: '/evidence/usb', motd: 'USB image mounted at /evidence/usb.\n', files };
      },
      hints: ['Opening 48 files one at a time would work but is slow. Which command checks a file\'s real type?', '`file` accepts many files at once. Then filter its output for anything that is not JPEG.', '`file DCIM/*.jpg | grep -v JPEG`'],
      writeup: {
        how: '`file DCIM/*.jpg` reports JPEG image data for 47 files. Filtering with `grep -v JPEG` leaves one that is a PDF document despite its `.jpg` name. Its metadata title is "Site access codes".',
        why: 'Renaming a file is the simplest way to hide it from a casual look, and it works surprisingly often. Signature checks catch it instantly, which is why they are one of the first things forensic tools run.',
        fix: 'Data loss prevention tools should inspect file content rather than trusting extensions, and removable media in restricted areas should be controlled.'
      }
    },
    {
      id: 'forensics-author',
      title: 'Who made the leak?',
      difficulty: 'easy',
      points: 100,
      skills: ['exiftool', 'PDF metadata', 'strings'],
      prepare: ['forensics-metadata'],
      brief: 'A confidential board paper appeared on a public forum as a PDF. Larkfield\'s document system records who exported each PDF, but whoever leaked this one re-saved it. The document metadata survived anyway. The leaked copy and three internal versions are in `/evidence/leak`.',
      goal: 'Find the author recorded in the leaked file `board-paper-leaked.pdf` and submit it as `SOC{author}`.',
      flag: 'sobplElxyKnpB7oq',
      workspace: () => ({
        type: 'shell',
        cwd: '/evidence/leak',
        motd: 'The leaked PDF and the internal versions are in /evidence/leak.\n',
        files: {
          '/evidence/leak/board-paper-v1.pdf': pdf({ Title: 'Board paper: restructuring', Author: 'h.ward', Creator: 'Microsoft Word', CreationDate: 'D:20260302091000Z' }),
          '/evidence/leak/board-paper-v2.pdf': pdf({ Title: 'Board paper: restructuring', Author: 'h.ward', Creator: 'Microsoft Word', CreationDate: 'D:20260305163000Z' }),
          '/evidence/leak/board-paper-final.pdf': pdf({ Title: 'Board paper: restructuring (final)', Author: 'Larkfield Docs export', Creator: 'Larkfield Docs 4.2', CreationDate: 'D:20260309120000Z' }),
          '/evidence/leak/board-paper-leaked.pdf': pdf({ Title: 'Board paper: restructuring (final)', Author: 'd.walsh', Creator: 'Microsoft Print to PDF', Producer: 'Microsoft: Print To PDF', CreationDate: 'D:20260311224512Z' }),
          '/evidence/leak/forum-post.txt': 'Posted 12 March 2026 by user "lark_insider": thought people should see this before Friday.\n'
        }
      }),
      hints: ['Document metadata is stored inside the file. Which tool prints it?', '`exiftool` reads a PDF\'s info dictionary, including the Author field.', '`exiftool board-paper-leaked.pdf`, then compare with the internal versions.'],
      writeup: {
        how: '`exiftool board-paper-leaked.pdf` shows Author `d.walsh`, Creator "Microsoft Print to PDF" and a creation time of 22:45 UTC on 11 March, the night before it was posted. The internal versions were written by h.ward and exported by the document system, so the leaked copy was produced separately by printing the final version to PDF on a machine logged in as d.walsh.',
        why: 'Metadata often survives the steps people take to hide where a document came from. Here it gives investigators a user name, a method and a time to check against device and access logs. On its own it is a lead, not proof: Author fields can be edited, and a shared machine could be involved.',
        fix: 'Strip metadata from documents that leave the organisation, and log exports and printing of sensitive documents so a leak can be traced through systems rather than only through file contents.'
      }
    },
    {
      id: 'forensics-integrity',
      title: 'Has anything changed?',
      difficulty: 'medium',
      points: 150,
      skills: ['sha256sum -c', 'manifests', 'chain of custody'],
      prepare: ['forensics-handling'],
      brief: 'Evidence from a contractor\'s laptop was collected two weeks ago, and the collecting analyst wrote a SHA-256 manifest at the time. Since then the copy has passed through several hands. Before it goes to the legal team, someone has to confirm that every file is still exactly as collected.',
      goal: 'Verify the evidence against `MANIFEST.sha256` and submit the path of the file that no longer matches, exactly as the manifest lists it, as `SOC{path}`, for example `SOC{mail/export_001.txt}`.',
      flag: 'HfduHUR7KZG13MbRIjCaDuu66YosSg==',
      workspace: () => {
        const r = random(256);
        const files = {};
        const names = [];
        for (let i = 0; i < 36; i++) {
          const name = `${r.pick(['mail', 'docs', 'chat', 'browser'])}/${r.pick(['export', 'item', 'record', 'page'])}_${String(i).padStart(3, '0')}.${r.pick(['txt', 'csv', 'json', 'html'])}`;
          files[`/evidence/contractor/${name}`] = `record ${i}\n${'x'.repeat(r.int(20, 200))}\n`;
          names.push(name);
        }
        const manifest = names.map((n) => `${sha256(files[`/evidence/contractor/${n}`])}  ${n}`).join('\n') + '\n';
        // One file was quietly edited after collection: a single amount.
        const target = names[23];
        files[`/evidence/contractor/${target}`] = files[`/evidence/contractor/${target}`].replace('record 23', 'record 23 ');
        files['/evidence/contractor/MANIFEST.sha256'] = manifest;
        files['/evidence/contractor/CUSTODY.txt'] = 'Collected 27 Feb 2026 by A. Novak. Manifest written at collection.\nTransferred to R. Yilmaz 2 Mar 2026.\nTransferred to evidence store 6 Mar 2026.\n';
        return { type: 'shell', cwd: '/evidence/contractor', motd: 'Evidence copy in /evidence/contractor. Manifest: MANIFEST.sha256\n', files };
      },
      hints: ['Hashing all 36 files and comparing by eye would take a while. sha256sum can do the comparison itself.', '`sha256sum -c` reads a manifest and prints OK or FAILED for every file in it. Run it from the folder the paths are relative to.', '`sha256sum -c MANIFEST.sha256 | grep -v OK`'],
      writeup: {
        how: '`sha256sum -c MANIFEST.sha256` recomputes the hash of every listed file. Thirty five print OK and one prints FAILED, followed by a warning that one computed checksum did not match. The change is a single extra space, invisible when reading the file, but enough to change its hash completely.',
        why: 'If evidence cannot be shown to be unchanged, it may be excluded, and a single unexplained change casts doubt on everything else. Manifests and chain of custody records are what let you say exactly what changed, and when it could have happened.',
        fix: 'Keep evidence read only, work on copies, verify the manifest at each handover, and record the result in the custody log. Here the custody log tells you which handover to investigate.'
      }
    },
    {
      id: 'forensics-known-bad',
      title: 'Seen it before',
      difficulty: 'medium',
      points: 150,
      skills: ['sha256sum', 'grep -f', 'hash sets'],
      prepare: ['forensics-hashing'],
      brief: 'A user\'s Downloads folder has 60 files in it, and threat intelligence has shared a list of 200 hashes linked to a campaign targeting your sector. One of the files on the laptop is on that list. There is also a file whose name appears on the list, which is exactly the kind of thing that sends investigators the wrong way.',
      goal: 'Find the file in `~/Downloads` whose SHA-256 is on `/intel/campaign.sha256` and submit its name as `SOC{name}`.',
      flag: 'c7JJ6dVtgVS4pzUM16o95/eLGeghI9tgjDkF',
      workspace: () => {
        const r = random(6060);
        const files = {};
        const listed = [];
        const kinds = [['pdf', () => pdf({ Title: 'Document', Author: 'user' })], ['zip', () => zip('readme.txt', `item ${r.int(1, 9999)}`)], ['exe', () => exe(r.int(1, 99999))], ['jpg', () => jpeg(r.int(1, 99999))], ['txt', () => `note ${r.int(1, 99999)}\n`]];
        const base = ['setup', 'invoice', 'photo', 'report', 'driver', 'update', 'notes', 'statement', 'agenda', 'menu', 'scan', 'contract'];
        for (let i = 0; i < 60; i++) {
          const [ext, make] = r.pick(kinds);
          files[`/home/learner/Downloads/${r.pick(base)}_${r.int(100, 999)}${i}.${ext}`] = make();
        }
        files['/home/learner/Downloads/ChromeSetup.exe'] = exe(4242);
        files['/home/learner/Downloads/meeting_notes_0311.zip'] = zip('meeting_notes.lnk', 'C:\\Windows\\System32\\cmd.exe /c start https://notes-viewer.test');
        for (let i = 0; i < 199; i++) listed.push([sha256(noise(10000 + i, 48)), `${r.pick(base)}_${r.int(1000, 9999)}.${r.pick(['exe', 'zip', 'dll', 'js'])}`]);
        listed.splice(87, 0, [sha256(files['/home/learner/Downloads/meeting_notes_0311.zip']), 'Q1_notes.zip']);
        listed.splice(140, 0, [sha256(noise(777, 32)), 'ChromeSetup.exe']);
        files['/intel/campaign.sha256'] = listed.map(([h, n]) => `${h}  ${n}`).join('\n') + '\n';
        return { type: 'shell', cwd: '/home/learner', motd: 'Intelligence list: /intel/campaign.sha256. Files to check: ~/Downloads\n', files };
      },
      hints: ['Compare hashes, not names. The name match is a decoy.', 'Hash every file in Downloads, then search that output for any hash on the list. `grep -f FILE` takes its patterns from a file.', '`cut -d" " -f1 /intel/campaign.sha256 > bad.txt` then `sha256sum Downloads/* | grep -f bad.txt`'],
      writeup: {
        how: 'Extracting the hash column of the intelligence list and running `sha256sum Downloads/* | grep -f bad.txt` returns one line: `meeting_notes_0311.zip`, which the list knows as `Q1_notes.zip`. It is a ZIP holding a Windows shortcut. `ChromeSetup.exe` shares a name with an entry on the list, but its hash is different, so it is a different file.',
        why: 'Attackers rename files constantly and legitimate software shares names with malware all the time. Hash matching cuts through both. Being able to check hundreds of hashes against a list in one command is basic, everyday analyst work.',
        fix: 'Load campaign hashes into endpoint protection so matches are blocked automatically, and have the mail and web gateways check them too.'
      }
    },
    {
      id: 'forensics-png-comment',
      title: 'A comment in the picture',
      difficulty: 'medium',
      points: 200,
      skills: ['exiftool', 'PNG chunks', 'base64 -d'],
      prepare: ['forensics-metadata'],
      brief: 'A screenshot was posted to a public image board, and a monitoring service flagged it because the same account has leaked Larkfield material before. The image itself shows nothing sensitive. The analyst who looked at it wondered whether the file carries anything besides the picture.',
      goal: 'Examine `/evidence/board/screenshot.png`, find the text hidden in its metadata, decode it and submit the flag.',
      flag: 'P4rO1h9nzAWjxz8NBINrXg+ofSZC+GnQkockWCdY8MRKP/zAMVA9xjURIQ==',
      workspace: (flag) => ({
        type: 'shell',
        cwd: '/evidence/board',
        motd: 'Posted image saved as /evidence/board/screenshot.png\n',
        files: {
          '/evidence/board/screenshot.png': png({ width: 1280, height: 720, seed: 1280, size: 2400, text: [['Software', 'Greenshot 1.3'], ['Creation Time', '2026:03:12 21:14:03'], ['Comment', toBase64(utf8(`handover: ${flag}`))]] }),
          '/evidence/board/post.txt': 'Post by lark_insider, 12 March 2026: "nothing to see here ;)"\n'
        }
      }),
      hints: ['The picture is innocent. Look at what the file says about itself.', '`exiftool` shows PNG text chunks. One of them is not like the others.', 'Copy the Comment value and run `echo <value> | base64 -d`.'],
      writeup: {
        how: '`exiftool screenshot.png` lists three text chunks. Software and Creation Time are normal for a screenshot tool. Comment holds a Base64 string, recognisable by its alphabet and padding. `base64 -d` turns it back into the handover message with the flag.',
        why: 'Metadata fields are an easy place to pass small amounts of data in plain sight, because images are shared everywhere and almost nobody looks inside them. Image boards and messaging apps do not always strip these chunks.',
        fix: 'Strip metadata from images on upload, and in investigations always check text chunks and trailing data, not just what the image shows.'
      }
    },
    {
      id: 'forensics-timeline',
      title: 'Three minutes on the web server',
      difficulty: 'medium',
      points: 200,
      skills: ['find -newermt', 'ls --full-time', 'timelines'],
      prepare: ['forensics-timeline'],
      brief: 'The web server logs show an attacker\'s first request at 02:41 UTC on 13 March 2026, and the server was taken offline at 03:00. You have a copy of the web root with its original timestamps. The team needs to know what the attacker touched, starting with the very first file they changed.',
      goal: 'Find every file under `/srv/www` modified between 02:41 and 03:00 UTC on 13 March 2026, and submit the full path of the earliest one as `SOC{path}`.',
      flag: '/mWRVFaZQsBNaPD1TGPEr5lSEox8F2cO2vpxl3W4iW8PBxpkh7w=',
      workspace: () => {
        const r = random(241);
        const files = {};
        const pages = ['index.php', 'about.php', 'contact.php', 'products.php', 'cart.php', 'login.php', 'account.php', 'search.php', 'footer.php', 'header.php', 'config.php', 'lib/db.php', 'lib/auth.php', 'lib/mail.php', 'lib/util.php'];
        for (const page of pages) files[`/srv/www/${page}`] = { content: `<?php // ${page} ?>\n`, mtime: at(r.int(1, 10), r.int(8, 18), r.int(0, 59), r.int(0, 59)) };
        for (let i = 0; i < 90; i++) files[`/srv/www/static/img/p${i}.png`] = { content: png({ seed: i, size: 80 }), mtime: at(r.int(1, 12), r.int(8, 18), r.int(0, 59)) };
        for (let i = 0; i < 25; i++) files[`/srv/www/uploads/user_${100 + i}.jpg`] = { content: jpeg(i, 200), mtime: at(r.int(5, 13), r.int(0, 23), r.int(0, 59), r.int(0, 59)) };
        // Legitimate activity just outside the window.
        files['/srv/www/uploads/user_131.jpg'] = { content: jpeg(131, 200), mtime: at(13, 2, 38, 12) };
        files['/srv/www/cache/sitemap.xml'] = { content: '<?xml version="1.0"?><urlset/>\n', mtime: at(13, 3, 0, 1) };
        // The attacker.
        files['/srv/www/uploads/user_132.jpg.php'] = { content: '<?php /* uploaded script */ ?>\n', mtime: at(13, 2, 42, 9) };
        files['/srv/www/lib/util.php'] = { content: '<?php // util.php, with an extra include added ?>\n', mtime: at(13, 2, 44, 30) };
        files['/srv/www/static/img/.cache.php'] = { content: '<?php /* second copy */ ?>\n', mtime: at(13, 2, 47, 55) };
        files['/srv/www/config.php'] = { content: '<?php // config.php ?>\n', mtime: at(13, 2, 51, 2) };
        return { type: 'shell', cwd: '/srv/www', motd: 'Web root copy at /srv/www, original timestamps preserved.\n', files };
      },
      hints: ['find can select files by modification time. You need a lower bound at 02:41 and an upper bound at 03:00.', '`find /srv/www -type f -newermt "2026-03-13 02:41" ! -newermt "2026-03-13 03:00"` gives the window. Then you need their exact times to put them in order.', 'Pass the results to `ls -lt --full-time` (for example with `xargs`) and read the bottom line, or use `stat` on each one.'],
      writeup: {
        how: '`find /srv/www -type f -newermt "2026-03-13 02:41" ! -newermt "2026-03-13 03:00"` returns four files. `ls -lt --full-time` on them puts them in order: `uploads/user_132.jpg.php` at 02:42:09 (a script uploaded through the image upload form with a double extension), then `lib/util.php` modified at 02:44:30, a hidden `static/img/.cache.php` at 02:47:55, and `config.php` read and rewritten at 02:51:02. The upload at 02:38 and the sitemap at 03:00:01 are just outside the window. Note the hidden file: `ls` without `-a` would not show it.',
        why: 'The first file an attacker creates usually tells you how they got in. Here, an upload form accepted a file ending in `.php`. The later files show them making sure they could come back, by adding code to an existing library file and hiding a second copy among the images.',
        fix: 'Validate uploads by content and store them outside the web root, never let the server execute files in upload folders, and use file integrity monitoring so changes to code files raise an alert in real time.'
      }
    },
    {
      id: 'forensics-carve',
      title: 'What was on the card',
      difficulty: 'hard',
      points: 300,
      skills: ['binwalk', 'dd', 'carving', 'sha256sum'],
      prepare: ['forensics-carving', 'forensics-hashing'],
      brief: 'A memory card was formatted before it was seized, so there is no filesystem left to list its files. The raw image is in `/evidence/card.img`. Formatting removed the index, not the data, so the files are still in there, packed one after another.\n\nThe legal team only cares about the document on the card, and they need its hash to compare with a copy they received from another source.',
      goal: 'Carve the PDF out of the card image exactly, hash it, and submit the first 12 characters of its SHA-256 as `SOC{hash}`.',
      flag: '6yGXgIfmxfOfCOILSHgQjDI=',
      workspace: () => {
        const parts = [
          new Uint8Array(512),
          jpeg(1, 2300),
          png({ seed: 2, size: 900, text: [['Software', 'Camera 2.1']] }),
          jpeg(3, 1800),
          pdf({ Title: 'Supplier contract 2026', Author: 'k.mensah', Creator: 'Larkfield Docs 4.2', CreationDate: 'D:20260301090000Z' }, 'BT (Agreed price: 41,200 per quarter) Tj ET'),
          zip('notes.txt', 'meet at 6, bring the printed copy\n'),
          jpeg(4, 1200),
          new Uint8Array(700)
        ];
        return { type: 'shell', cwd: '/evidence', motd: 'Raw card image at /evidence/card.img. There is no filesystem to mount.\n', files: { '/evidence/': { owner: 'learner' }, '/evidence/card.img': concat(...parts) } };
      },
      hints: ['There is no filesystem, so ls inside the image is not possible. Scan the raw bytes for known signatures.', '`binwalk card.img` lists every signature with its decimal offset. The PDF runs from its own offset up to where the next file begins.', 'With bs=1, `skip` is the PDF offset and `count` is the next offset minus the PDF offset: `dd if=card.img of=doc.pdf bs=1 skip=START count=LENGTH`, then `sha256sum doc.pdf`.'],
      writeup: {
        how: '`binwalk card.img` finds three JPEGs, a PNG, a PDF and a ZIP at increasing offsets. The PDF ends exactly where the ZIP begins, so its length is the ZIP offset minus the PDF offset. Carving with `dd bs=1 skip=<pdf offset> count=<length>` produces a file that `file` recognises as a PDF, `exiftool` reads as "Supplier contract 2026", and `sha256sum` hashes. Carving to the end of the image instead would include the ZIP and the following JPEG, and give a completely different hash.',
        why: 'Formatting and deleting usually only remove the index of where files are, not their contents. Carving recovers them from raw bytes and is a standard technique on memory cards, disk images and memory dumps. Precision matters: to compare with another copy or a known hash, you have to recover exactly the original bytes.',
        fix: 'To really remove data, use full overwrite or encryption with key destruction, which is what secure erase and full disk encryption provide. For investigators, always record the offsets and lengths you carved so someone else can reproduce the result.'
      }
    }
  ]
};
