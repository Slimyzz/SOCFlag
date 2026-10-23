# HiddenWell

**HiddenWell is a free, browser-only platform for learning defensive cybersecurity by doing it.** You read a short lesson, try the idea in the same activity, and then investigate synthetic evidence to capture a flag. Everything runs in your browser. There is no server to talk to, nothing to install, and no account to create.

> **Live demo:** _add your Cloudflare Pages URL here once deployed_

The focus is blue-team work: analysing logs, email, files and network traffic to work out what happened, rather than attacking systems. Learners investigate realistic but entirely synthetic evidence; there is no offensive tooling and no exploit code anywhere in the project.

## What is inside

Eight topics, worked in order, each a run of short lessons followed by capture-the-flag challenges. **44 lessons and 56 challenges** in total.

| Topic | What you investigate |
| --- | --- |
| **Linux fundamentals** | The terminal, files, permissions, and pipelines, in a real in-browser shell |
| **Log investigation** | Authentication, web and Windows logs in a SIEM: brute force, spraying, detections, timelines |
| **Email and phishing analysis** | Headers, SPF/DKIM/DMARC, lookalike domains, links and attachment triage |
| **File forensics** | Signatures, hashing, metadata, file timelines, carving, and evidence integrity |
| **Network traffic analysis** | Packet captures: handshakes, scans, DNS, cleartext protocols, and traffic patterns |
| **Secure code review** | Reading code as a defender: injection, XSS, access control, secrets and path handling |
| **CVE case studies** | How flaws are scored and prioritised, and how landmark vulnerabilities were detected and fixed |
| **Incident response capstone** | One incident, investigated end to end across the mailbox, SIEM, packet capture and host |

Each challenge hides a flag that looks like `HW{...}`. There are graded checks inside lessons, local hints, a write-up after each solve (how it works, why it matters, how to prevent it), and a spaced-repetition review deck for the key terms. Progress is saved in your browser only.

## Screenshots

_Add screenshots to `docs/screenshots/` and reference them here, for example:_

```
docs/screenshots/home.png        the landing page
docs/screenshots/siem.png        the SIEM search workspace
docs/screenshots/packets.png     the packet capture viewer
docs/screenshots/challenge.png   a challenge with its write-up
```

## Run it locally

Requirements: **Node.js 20 or later**. There are no dependencies to install and no build step.

```bash
npm start
```

Then open **http://localhost:8080**. `npm start` runs a tiny static file server (`tools/serve.js`); any static server pointed at the project root works just as well, because the site is plain HTML, CSS and ES modules.

## Tests

```bash
npm test
```

The suite (`node --test`) covers:

- **Content validation** – every section, lesson and challenge is well formed, and ids and cross-references are valid.
- **Solvability** – every challenge is solved through its intended path against its own generated data, and the result matches the sealed flag.
- **The flag guarantee** – no plaintext flag appears anywhere in the shipped source.
- **The query language** – unit tests for the SIEM search language (HQL).
- **The shell** – unit tests for the in-browser Linux shell and its commands.

## How it works

HiddenWell is a static site (version 3): `index.html` plus ES modules, with no framework and no build.

```text
index.html                 shell, routed with the URL hash
assets/js/
  app.js                   router and every page
  core/                    local progress store, DOM and Markdown helpers
  lib/                     bytes, hashing, flag sealing, the SIEM query language, email parsing
  shell/                   the in-browser Linux shell (virtual filesystem, parser, ~80 commands)
  ui/                      the terminal, lesson blocks, and the SIEM, mailbox, packet and tools workspaces
content/
  *.js                     the curriculum: one file per topic, each with lessons and challenges
  index.js                 registers the topics in order
tools/serve.js             the zero-dependency dev server
test/                      the test suite and the intended solutions
```

Every workspace (the terminal, the SIEM, the mailbox, the packet viewer, the analyst tools) is a small program running on the page, working on evidence generated deterministically in the browser. Nothing reaches the network or your real files.

### About the flags

Because the whole site runs on the visitor's computer, a determined person could dig the answers out of the code. The guarantee HiddenWell makes is narrow and honest: **no plaintext flag exists anywhere in the source.** Flags are stored sealed (XOR'd with a keystream derived from the challenge id, then Base64), so searching the source for `HW{` finds nothing, and the page unseals a flag only to check your answer. That is enough for a learning lab; it is not, and does not claim to be, real secrecy. A test enforces the guarantee on every build.

Flags are never committed in plaintext. The author-only scripts that produce the sealed values live **outside** this repository.

## Deploy

The site is static, so it hosts anywhere. It is built for **Cloudflare Pages**:

- Framework preset: **None**. Build command: **(none)**. Output directory: **`/`** (the repository root).
- `_headers` ships a strict Content Security Policy and related security headers. Because the app loads only its own files, the policy is `default-src 'none'` with narrow allowances for the site's own scripts, styles, fonts and images.

## License

MIT. See [LICENSE](LICENSE).

Fonts are bundled under the SIL Open Font License: **Atkinson Hyperlegible** by the Braille Institute, and **JetBrains Mono**.
