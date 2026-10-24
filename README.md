<p align="center">
  <img src="docs/logo.svg" width="88" alt="HiddenWell logo">
</p>

<h1 align="center">HiddenWell</h1>

<p align="center">
  <b>A blue-team CTF that runs entirely in your browser.</b><br>
  Investigate logs, phishing emails, files and packet captures. Find the flag.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/challenges-56-f2d04b?style=flat-square&labelColor=15202b" alt="56 challenges">
  <img src="https://img.shields.io/badge/lessons-44-8aabff?style=flat-square&labelColor=15202b" alt="44 lessons">
  <img src="https://img.shields.io/badge/dependencies-0-63c48f?style=flat-square&labelColor=15202b" alt="zero dependencies">
  <img src="https://img.shields.io/badge/license-MIT-e3e8ed?style=flat-square&labelColor=15202b" alt="MIT license">
</p>

<p align="center">
  <img src="docs/screenshots/home.png" alt="HiddenWell home page" width="900">
</p>

## What it is

Short lessons, then capture-the-flag challenges built on synthetic evidence. No install, no account, no server. Your progress stays in your browser.

| Topic | You investigate |
| --- | --- |
| Linux | Files, permissions and pipelines in a real in-browser shell |
| Logs | Brute force, password spraying and beacons in a SIEM |
| Email | Headers, SPF/DKIM/DMARC, lookalike domains, attachments |
| Forensics | Signatures, hashes, metadata, timelines, carving |
| Network | Handshakes, scans, DNS tunnelling, cleartext, exfiltration |
| Code review | Injection, XSS, access control, secrets, path traversal |
| CVEs | KEV triage, Log4Shell, WannaCry, exposure windows |
| Capstone | One incident, end to end, across every source |

## Inside

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/siem.png" alt="SIEM search"><p align="center"><b>SIEM</b> with its own query language</p></td>
    <td width="50%"><img src="docs/screenshots/packets.png" alt="Packet capture viewer"><p align="center"><b>Packet viewer</b> with filters and follow stream</p></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/capstone.png" alt="Incident response capstone"><p align="center"><b>Capstone</b> across mailbox, SIEM and capture</p></td>
    <td width="50%"><img src="docs/screenshots/challenges.png" alt="Challenge board"><p align="center"><b>56 challenges</b>, easy to hard</p></td>
  </tr>
</table>

## Run it

```bash
npm start      # http://localhost:8080
npm test       # 99 tests
```

Node 20+. No dependencies, no build step. Deploys as a static site.

## How it works

- **Everything is client side.** The shell, SIEM, mailbox and packet viewer are plain ES modules working on evidence generated in the page.
- **No plaintext flags.** Flags are sealed in the source and only unsealed to check an answer. A test fails the build if one ever leaks.
- **Every challenge is proven solvable.** The test suite solves all 56 through their intended path.
- **Locked down.** Strict Content Security Policy, no network access, no tracking.

## License

MIT. Fonts: Atkinson Hyperlegible and JetBrains Mono (SIL OFL).
