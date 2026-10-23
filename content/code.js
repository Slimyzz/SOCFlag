import { ran, random } from './helpers.js';

// A small Flask shop that the lessons review together. Every flaw in it is a
// common one, and each is shown next to the fix a reviewer should ask for.

const SHOP = {
  '/home/learner/shop/README.md': '# Larkfield shop\n\nFlask app for staff purchases. Run with `flask run`.\n',
  '/home/learner/shop/app.py': `from flask import Flask
from routes import orders, account, admin, files

app = Flask(__name__)
app.config.from_object("config")
app.register_blueprint(orders.bp)
app.register_blueprint(account.bp)
app.register_blueprint(admin.bp)
app.register_blueprint(files.bp)
`,
  '/home/learner/shop/config.py': `import os

DEBUG = False
DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ["SECRET_KEY"]
# TODO move this to the vault before go live
PAYMENTS_API_KEY = "lk_live_51Hq8Zt2eXb9mVfD3kR7wPq"
`,
  '/home/learner/shop/db.py': `import sqlite3

def connect():
    return sqlite3.connect("shop.db")

def query(sql, params=()):
    with connect() as conn:
        return conn.execute(sql, params).fetchall()
`,
  '/home/learner/shop/routes/orders.py': `from flask import Blueprint, request, session, abort
from db import query

bp = Blueprint("orders", __name__)

@bp.get("/orders")
def list_orders():
    rows = query("SELECT id, total FROM orders WHERE user_id = ?", (session["user_id"],))
    return {"orders": rows}

@bp.get("/orders/search")
def search_orders():
    term = request.args.get("q", "")
    rows = query(f"SELECT id, total FROM orders WHERE note LIKE '%{term}%'")
    return {"orders": rows}

@bp.get("/orders/<int:order_id>")
def get_order(order_id):
    rows = query("SELECT * FROM orders WHERE id = ?", (order_id,))
    if not rows:
        abort(404)
    return {"order": rows[0]}
`,
  '/home/learner/shop/routes/account.py': `import hashlib
from flask import Blueprint, request, session, abort
from db import query

bp = Blueprint("account", __name__)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@bp.post("/login")
def login():
    user = query("SELECT id, password_hash FROM users WHERE email = ?", (request.form["email"],))
    if not user or user[0][1] != hash_password(request.form["password"]):
        abort(401)
    session["user_id"] = user[0][0]
    return {"ok": True}
`,
  '/home/learner/shop/routes/admin.py': `import subprocess
from flask import Blueprint, request

bp = Blueprint("admin", __name__)

@bp.post("/admin/ping")
def ping_host():
    host = request.form["host"]
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}
`,
  '/home/learner/shop/routes/files.py': `import os
from flask import Blueprint, request, send_file

bp = Blueprint("files", __name__)
RECEIPTS = "/srv/shop/receipts"

@bp.get("/receipt")
def receipt():
    name = request.args["name"]
    return send_file(os.path.join(RECEIPTS, name))
`,
  '/home/learner/shop/templates/search.html': `<h1>Results</h1>
<p>You searched for {{ term | safe }}</p>
<ul>{% for o in orders %}<li>{{ o.id }}</li>{% endfor %}</ul>
`,
  '/home/learner/shop/static/basket.js': `const params = new URLSearchParams(location.search);
document.getElementById("greeting").innerHTML = "Welcome back, " + params.get("name");
document.getElementById("count").textContent = basket.length;
`
};

function lessonRepo(motd) {
  return { type: 'shell', motd, cwd: '/home/learner/shop', files: SHOP, hostname: 'review' };
}

export default {
  id: 'code',
  title: 'Secure code review',
  short: 'Code review',
  summary: 'Read code the way a defender does: follow untrusted input to dangerous places, recognise the common flaws, and choose fixes that actually work.',
  intro: 'Many incidents trace back to a single line of code. You do not need to be a developer to review code for security, but you do need to know where to look and what a good fix looks like. This topic uses a small Python web shop and teaches the habits reviewers use on real pull requests.',
  outcomes: [
    'Trace untrusted input from where it enters to where it is used',
    'Recognise SQL and command injection and ask for the right fix',
    'Spot output that will run in a browser, and how to make it safe',
    'Find missing access checks and weak password storage',
    'Find secrets in code and know what to do when one leaks',
    'Spot unsafe file path handling'
  ],
  lessons: [
    {
      id: 'code-mindset',
      title: 'Sources, sinks and trust',
      summary: 'Where untrusted data comes in, where it can do damage, and how reviewers search a codebase.',
      minutes: 11,
      terms: [
        ['source', 'Anywhere untrusted data enters a program: request parameters, form fields, headers, cookies, uploaded files, even data read back from the database.'],
        ['sink', 'A place where data can cause harm if an attacker controls it: a database query, a shell command, HTML sent to a browser, a file path, a redirect.'],
        ['trust boundary', 'The line between data you control and data you do not. Everything crossing it has to be checked or handled safely.'],
        ['taint', 'Following untrusted data through a program. If it reaches a sink without being made safe, there is likely a vulnerability.']
      ],
      workspace: lessonRepo('Larkfield shop source code. Try: ls -R\n'),
      blocks: [
        { type: 'text', body: 'Security review is not reading every line hoping something jumps out. Reviewers ask one question over and over: **can someone outside control this value, and where does it end up?** Untrusted data enters through **sources** and causes harm at **sinks**. A vulnerability is usually a path from one to the other with nothing safe in between.' },
        { type: 'table', head: ['Sources in a web app', 'Sinks to look for'], rows: [['`request.args`, `request.form`, `request.json`', 'SQL queries built from strings'], ['Headers and cookies', 'Shell commands, especially with `shell=True`'], ['Uploaded files and their names', 'HTML output marked safe, or `innerHTML` in JavaScript'], ['The URL path', 'File paths built with user input'], ['Data from other systems', 'Redirects, deserialisation, eval']] },
        { type: 'text', body: 'On a large codebase, start from the sinks. Search for the dangerous functions, then read backwards to see where their input came from. `grep -rn` is enough to begin with.' },
        { type: 'example', title: 'Searching for sinks', steps: [
          { cmd: 'grep -rn "query(" routes/', note: 'Every database call in the routes.' },
          { cmd: 'grep -rn "shell=True" .', note: 'Commands run through a shell.' },
          { cmd: 'grep -rn "request\\." routes/', note: 'Every place request data is read: the sources.' },
          { cmd: 'grep -rn "| safe\\|innerHTML" templates/ static/', note: 'Places where output escaping is turned off.' }
        ] },
        { type: 'task', text: 'List every place in `routes/` that reads from `request`.', hint: '`grep -rn "request\\." routes/`', check: (log) => ran(log, 'grep', (a) => a.includes('request')) },
        { type: 'quiz', question: 'Data your own application wrote to the database earlier is read back and put into an HTML page. Is it trusted?', options: [
          { text: 'No. If a user supplied it originally, it is still untrusted', correct: true, why: 'Storing data does not clean it. Stored cross site scripting and second order SQL injection both work exactly this way: the dangerous value goes in through one feature and comes out through another.' },
          { text: 'Yes. It came from our own database', why: 'Where it is stored does not matter. Who chose its contents does.' },
          { text: 'Only if it is shorter than 100 characters', why: 'Length limits help a little but do not make data safe.' }
        ] },
        { type: 'note', title: 'Tools help, people decide', body: 'Static analysis tools such as Semgrep and CodeQL automate source to sink searches across a whole codebase and are well worth running. They also produce false positives and miss logic flaws, so a human still has to read the code paths they flag.' }
      ]
    },
    {
      id: 'code-injection',
      title: 'Injection: SQL and commands',
      summary: 'Why building queries and commands from strings is dangerous, and the fixes that work.',
      minutes: 14,
      terms: [
        ['injection', 'When input is treated as part of a command or query instead of as data, so the person supplying it can change what runs.'],
        ['parameterised query', 'A query with placeholders such as `?`, where values are sent separately from the SQL. The database never confuses them with code.'],
        ['allow list', 'A fixed set of permitted values. Anything not on the list is rejected. The safe way to handle things that cannot be parameters, such as column names.'],
        ['shell=True', 'A Python subprocess option that runs the command through a shell, which interprets characters such as `;`, `|` and `$( )`.']
      ],
      workspace: lessonRepo('Larkfield shop. Try: cat routes/orders.py\n'),
      blocks: [
        { type: 'text', body: 'SQL injection happens when user input is pasted into the text of a query. The database cannot tell which parts the developer wrote and which came from the user, so carefully chosen input changes the meaning of the query: reading other people\'s data, bypassing logins, or changing records.' },
        { type: 'task', text: 'Read `routes/orders.py`.', check: (log) => ran(log, 'cat', (a) => a.includes('orders.py')) },
        { type: 'spot', question: 'Which line builds a query from user input?', code: '@bp.get("/orders/search")\ndef search_orders():\n    term = request.args.get("q", "")\n    rows = query(f"SELECT id, total FROM orders WHERE note LIKE \'%{term}%\'")\n    return {"orders": rows}', line: 4, explain: 'The f-string inserts `term` straight into the SQL text. Quotes in the search term end the string early and whatever follows is read as SQL. Also notice what is missing: unlike `list_orders`, this query is not limited to the current user, so even honest searches see everyone\'s orders.', nudge: 'Look for user input inside the SQL text itself.' },
        { type: 'quiz', question: 'Which fix should the reviewer ask for?', code: 'A: term = term.replace("\'", "")\nB: query("SELECT id, total FROM orders WHERE note LIKE ? AND user_id = ?", (f"%{term}%", session["user_id"]))\nC: if ";" in term: abort(400)\nD: term = html.escape(term)', options: [
          { text: 'B: pass the value as a parameter, and limit it to the user\'s own orders', correct: true, why: 'Parameters keep data and SQL separate, so no input can change the query\'s structure. Adding `user_id` fixes the second problem the review found.' },
          { text: 'A: strip single quotes', why: 'Removing characters is fragile: other encodings, other contexts (numbers need no quotes at all) and other databases break it. It also mangles legitimate input.' },
          { text: 'C: reject semicolons', why: 'Many injections need no semicolon. Block lists like this always miss something.' },
          { text: 'D: HTML escape it', why: 'HTML escaping protects browsers, not databases. It is the right tool for a different sink.' }
        ] },
        { type: 'text', body: 'Some parts of a query cannot be parameters, such as a column name for sorting. For those, compare the input against an **allow list** of known good values and use your own string, never the user\'s.' },
        { type: 'code', body: 'SORTABLE = {"date": "created_at", "total": "total"}\ncolumn = SORTABLE.get(request.args.get("sort"), "created_at")\nrows = query(f"SELECT id, total FROM orders WHERE user_id = ? ORDER BY {column}", (uid,))', caption: 'The column name comes from the dictionary, never from the request.' },
        { type: 'text', body: '**Command injection** is the same mistake with a shell. When a command is built as a string and run with `shell=True`, characters like `;` and `|` let input add commands of its own.' },
        { type: 'task', text: 'Find the command that runs through a shell.', hint: '`grep -rn "shell=True" .`', check: (log) => ran(log, 'grep', (a) => a.includes('shell')) },
        { type: 'quiz', question: 'What is the right fix for `subprocess.run(f"ping -c 1 {host}", shell=True)`?', options: [
          { text: 'Validate `host` as a hostname or IP, then call `subprocess.run(["ping", "-c", "1", host])` without a shell', correct: true, why: 'A list of arguments goes straight to the program with no shell to interpret special characters, and validating the format stops input such as a leading `-` being read as an option.' },
          { text: 'Wrap `host` in double quotes inside the f-string', why: 'Quotes can be closed by the input, and `$( )` still runs inside double quotes.' },
          { text: 'Run the web app as root so ping always works', why: 'That makes any injection far more damaging, not less likely.' }
        ] },
        { type: 'note', title: 'Better still', body: 'Ask whether the feature needs a shell command at all. Many can be replaced with a library call. A ping feature on an admin page may simply be unnecessary.' }
      ]
    },
    {
      id: 'code-xss',
      title: 'Output and the browser',
      summary: 'Cross site scripting, why templates escape by default, and the places where escaping gets switched off.',
      minutes: 11,
      terms: [
        ['cross site scripting (XSS)', 'When input ends up in a page as HTML or script, so it runs in other users\' browsers with the site\'s privileges.'],
        ['output encoding', 'Converting characters such as `<` and `"` into safe forms like `&lt;` so the browser shows them as text instead of reading them as markup.'],
        ['innerHTML', 'A browser property that parses a string as HTML. `textContent` sets plain text instead.'],
        ['Content Security Policy', 'A response header that tells the browser which scripts may run. A strong policy limits the damage when an XSS bug slips through.']
      ],
      workspace: lessonRepo('Larkfield shop. Try: cat templates/search.html static/basket.js\n'),
      blocks: [
        { type: 'text', body: 'Anything an application sends to a browser is interpreted by that browser. If user input ends up in the page as HTML rather than text, it can add script that runs as if the site itself wrote it: reading what the user sees, acting as them, or sending their session elsewhere. That is **cross site scripting**.' },
        { type: 'text', body: 'Modern template engines, including Jinja in Flask, escape output by default, so `{{ term }}` is safe. The danger is in the places where developers turn escaping off.' },
        { type: 'task', text: 'Read `templates/search.html`.', check: (log) => ran(log, 'cat', (a) => a.includes('search.html')) },
        { type: 'spot', question: 'Which line puts the search term into the page without escaping?', code: '<h1>Results</h1>\n<p>You searched for {{ term | safe }}</p>\n<ul>{% for o in orders %}<li>{{ o.id }}</li>{% endfor %}</ul>', line: 2, explain: '`| safe` tells Jinja the value is already trusted HTML and must not be escaped. It is meant for HTML the application generated itself, never for user input. Removing `| safe` is the fix.', nudge: 'Look for a filter that switches escaping off.' },
        { type: 'spot', question: 'Same problem, in browser JavaScript. Which line is unsafe?', code: 'const params = new URLSearchParams(location.search);\ndocument.getElementById("greeting").innerHTML = "Welcome back, " + params.get("name");\ndocument.getElementById("count").textContent = basket.length;', line: 2, explain: 'A value from the URL goes into `innerHTML`, so anyone who can get a user to open a crafted link controls part of the page. `textContent` sets plain text and is the fix. Line 3 already does it correctly.', nudge: 'Which property parses its value as HTML?' },
        { type: 'quiz', question: 'The team says they will fix XSS by deleting `<script>` from all input. Why is that not enough?', options: [
          { text: 'HTML can run script in many other ways, such as event attributes and links', correct: true, why: 'Image error handlers, SVG, `javascript:` links and dozens of other forms do not use a script tag at all. Encoding output for the context it lands in is reliable; trying to remove dangerous input is not.' },
          { text: 'It is enough if the filter is case insensitive', why: 'Case is the least of it. There are many ways to run script without that tag.' },
          { text: 'Browsers no longer run inline script', why: 'They do, unless a Content Security Policy forbids it.' }
        ] },
        { type: 'note', title: 'Defence in depth', body: 'A Content Security Policy that disallows inline script and only allows scripts from your own origin turns many XSS bugs into harmless ones. It is not a replacement for escaping, but it is a valuable second layer. This site uses one.' }
      ]
    },
    {
      id: 'code-access',
      title: 'Access control and passwords',
      summary: 'Checking who may see what on every request, and storing passwords properly.',
      minutes: 13,
      terms: [
        ['authentication', 'Checking who someone is, for example with a password.'],
        ['authorisation', 'Checking what that person is allowed to do. Being logged in is not the same as being allowed to see a particular record.'],
        ['IDOR', 'Insecure direct object reference. When changing an ID in a request, such as `/orders/1002`, shows someone else\'s data because the server never checks ownership.'],
        ['password hashing', 'Storing a slow, salted one way hash of a password instead of the password. bcrypt, scrypt and Argon2 are designed for it; MD5 and SHA-256 alone are far too fast.']
      ],
      workspace: lessonRepo('Larkfield shop. Try: cat routes/orders.py routes/account.py\n'),
      blocks: [
        { type: 'text', body: 'Broken access control tops the OWASP Top 10 for a reason. It is easy to write and invisible in normal testing: everything works for the person who owns the data. The flaw only appears when someone asks for data that is not theirs.' },
        { type: 'spot', question: 'In `routes/orders.py`, which line should check that the order belongs to the logged in user, and does not?', code: '@bp.get("/orders/<int:order_id>")\ndef get_order(order_id):\n    rows = query("SELECT * FROM orders WHERE id = ?", (order_id,))\n    if not rows:\n        abort(404)\n    return {"order": rows[0]}', line: 3, explain: 'The query looks the order up by ID only. Any logged in user can request `/orders/1`, `/orders/2` and so on and read every order. The query should include `AND user_id = ?` with the session user, or the code should check ownership before returning it.', nudge: 'What stops user A from reading user B\'s order?' },
        { type: 'quiz', question: 'The front end only shows each user links to their own orders. Does that protect the endpoint?', options: [
          { text: 'No. Anyone can send any request directly; checks must happen on the server', correct: true, why: 'Hiding links is a usability feature. Requests can be crafted by hand, by scripts or with browser tools, so every endpoint has to check permissions itself.' },
          { text: 'Yes, because users cannot see other order IDs', why: 'IDs are often sequential and easy to guess. Hiding them is not a control.' },
          { text: 'Yes, if the IDs are long random numbers', why: 'Unguessable IDs make attacks harder but are not access control. IDs leak through logs, emails and shared links.' }
        ] },
        { type: 'task', text: 'Find how passwords are hashed in this app.', hint: '`grep -rn "hash" routes/`', check: (log) => ran(log, 'grep', (a) => a.includes('hash')) },
        { type: 'spot', question: 'What is wrong in this login code?', code: 'def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n\n@bp.post("/login")\ndef login():\n    user = query("SELECT id, password_hash FROM users WHERE email = ?", (request.form["email"],))', line: 2, explain: 'Unsalted MD5. If the users table ever leaks, a modern graphics card can test billions of MD5 guesses per second, and identical passwords have identical hashes. Use a password hashing function with a per user salt and a tunable cost, such as Argon2id or bcrypt, through a maintained library.', nudge: 'Think about what happens if the database leaks.' },
        { type: 'order', question: 'Order these from weakest to strongest way to store passwords.', items: ['Plain text', 'Encrypted with a key stored on the same server', 'SHA-256 without salt', 'SHA-256 with a salt', 'bcrypt or Argon2id with a salt and a work factor'], explain: 'Encryption is reversible by anyone who gets the key, which usually leaks along with the data. Fast hashes are better but still allow huge guessing rates. Slow, salted password hashes are the standard.' },
        { type: 'note', title: 'Also check', body: 'Session handling (secure, HttpOnly cookies, logout that really ends the session), rate limits on login, and that admin routes check for an admin role rather than just a logged in user.' }
      ]
    },
    {
      id: 'code-secrets',
      title: 'Secrets in code',
      summary: 'How keys and passwords end up in repositories, how to find them, and what to do when one leaks.',
      minutes: 10,
      terms: [
        ['secret', 'Anything that grants access: API keys, passwords, tokens, private keys, connection strings.'],
        ['secret scanning', 'Searching code and its history for patterns that look like secrets. Tools include gitleaks, trufflehog and the scanners built into code hosting platforms.'],
        ['rotation', 'Replacing a secret with a new one and revoking the old one. The only real fix once a secret has leaked.']
      ],
      workspace: lessonRepo('Larkfield shop. Try: grep -rni "key" .\n'),
      blocks: [
        { type: 'text', body: 'Secrets end up in code because it is convenient: a key pasted in "just for testing", a config file committed by accident, a TODO that never got done. Once pushed, a secret is copied to every clone and stays in the history even after the line is deleted.' },
        { type: 'task', text: 'Search the project for anything that looks like a key or password.', hint: '`grep -rniE "key|secret|password|token" .`', check: (log) => ran(log, 'grep', (a) => /key|secret|token|password/i.test(a)) },
        { type: 'spot', question: 'Which line in `config.py` is a problem?', code: 'import os\n\nDEBUG = False\nDATABASE_URL = os.environ["DATABASE_URL"]\nSECRET_KEY = os.environ["SECRET_KEY"]\n# TODO move this to the vault before go live\nPAYMENTS_API_KEY = "lk_live_51Hq8Zt2eXb9mVfD3kR7wPq"', line: 7, explain: 'A live payments key in source code. Everyone with access to the repository, every build server and every backup now has it. The other settings show the right pattern: read from the environment, which is filled from a secrets manager at deploy time.', nudge: 'One of these values is written into the file itself.' },
        { type: 'quiz', question: 'A developer notices the key, deletes the line and pushes a new commit. Is the problem solved?', options: [
          { text: 'No. The key is still in the history and must be rotated', correct: true, why: 'Anyone can check out the earlier commit. Deleting it is good housekeeping, but the only fix for a leaked secret is to revoke it and issue a new one, then check the provider\'s logs for use of the old one.' },
          { text: 'Yes, as long as the new commit is pushed quickly', why: 'Automated scanners watch public repositories and find keys within minutes. And private repositories leak too.' },
          { text: 'Yes, if the repository is private', why: 'Private repositories are cloned to laptops and CI systems and get leaked or shared. Treat any committed secret as exposed.' }
        ] },
        { type: 'text', body: 'Secrets leak through logs too. A request logger that records full headers will capture authorization tokens; an error page in debug mode may print the whole configuration. Reviewers check what gets logged as well as what gets committed.' },
        { type: 'note', title: 'Prevent it next time', body: 'Run a secret scanner as a pre-commit hook and in CI, use a secrets manager instead of config files, and give keys the least privilege they need so a leak does less damage.' }
      ]
    },
    {
      id: 'code-files',
      title: 'Files and paths',
      summary: 'Path traversal, why joining paths is not enough, and handling uploads safely.',
      minutes: 11,
      terms: [
        ['path traversal', 'Using `../` or an absolute path in input to reach files outside the folder the application meant to use.'],
        ['canonical path', 'The real, absolute path after resolving `..`, `.` and links. Checks must be done on the canonical path.'],
        ['upload validation', 'Checking an uploaded file\'s real type, size and name, and storing it where it can never be executed.']
      ],
      workspace: lessonRepo('Larkfield shop. Try: cat routes/files.py\n'),
      blocks: [
        { type: 'text', body: 'Many features read files based on a request: download a receipt, show an avatar, open a report. If the file name comes from the user and is joined to a folder without checks, input such as `../../etc/passwd` walks out of that folder.' },
        { type: 'spot', question: 'Which line lets a request read files outside the receipts folder?', code: 'RECEIPTS = "/srv/shop/receipts"\n\n@bp.get("/receipt")\ndef receipt():\n    name = request.args["name"]\n    return send_file(os.path.join(RECEIPTS, name))', line: 6, explain: '`os.path.join` simply glues strings together. With `../` sequences the result leaves the folder, and if `name` is an absolute path, `os.path.join` discards `RECEIPTS` entirely and uses the user\'s path as it is.', nudge: 'What does joining a folder with `../../etc/passwd` give you?' },
        { type: 'quiz', question: 'Which fix is reliable?', options: [
          { text: 'Resolve the full path and check it is still inside the receipts folder (or use Flask\'s `send_from_directory`)', correct: true, why: 'Resolving first and checking the result handles `..`, absolute paths and links in one go. `send_from_directory` does exactly this for you. Better still, look receipts up by an ID that belongs to the user.' },
          { text: 'Remove `../` from the name', why: 'Tricks such as `....//` become `../` after one pass, and absolute paths need no dots at all.' },
          { text: 'Only allow names ending in .pdf', why: 'That still allows any PDF anywhere on the server.' }
        ] },
        { type: 'text', body: 'Uploads are the reverse problem: input becomes a file on the server. Check the real type from its bytes, not its name or the declared content type, generate your own file name, and store uploads outside the web root, somewhere the server will never execute them. The forensics topic showed what happens when an upload ending in `.php` lands in a folder the server runs code from.' },
        { type: 'order', question: 'Put these upload handling steps in a sensible order.', items: ['Check the size limit', 'Check the real file type from its first bytes', 'Generate a new random file name', 'Store it outside the web root', 'Serve it back with a fixed, safe content type'], explain: 'Each step removes one way the upload could be abused: resource exhaustion, disguised types, path tricks in names, execution on the server, and execution in the browser.' },
        { type: 'note', title: 'Other risky sinks', body: 'Deserialising untrusted data (Python\'s `pickle`, Java serialisation), fetching URLs supplied by users (server side request forgery) and redirects to user supplied addresses deserve the same source to sink questions.' }
      ]
    }
  ],
  challenges: [
    {
      id: 'code-sql-sink',
      title: 'One query of thirty',
      difficulty: 'easy',
      points: 100,
      skills: ['grep -rn', 'SQL injection', 'reviewing'],
      prepare: ['code-mindset', 'code-injection'],
      brief: 'The inventory service has about thirty database queries across its modules. A penetration test report says one search feature is injectable but does not say which. The developers would like the function name before they start.',
      goal: 'Find the function that builds an SQL query from request input without parameters and submit its name as `HW{function}`.',
      flag: '0fsMyQCOWk5F78Lkx/EA9Hr1HBZ0ZNNRtfM=',
      workspace: () => {
        const r = random(31);
        const tables = ['items', 'suppliers', 'locations', 'stock', 'transfers', 'audits'];
        const files = {};
        let n = 0;
        for (const table of tables) {
          const fns = [];
          for (let i = 0; i < 5; i++) {
            const name = `${r.pick(['get', 'find', 'list', 'count', 'lookup'])}_${table}_${['by_id', 'by_name', 'recent', 'by_site', 'by_owner'][i]}`;
            const column = ['id', 'name', 'created_at', 'site', 'owner'][i];
            const source = r.pick(['request.args.get("v")', 'request.args["v"]', 'request.json["v"]']);
            if (table === 'suppliers' && i === 1) {
              fns.push(`def ${name}():\n    value = ${source}\n    sql = "SELECT * FROM ${table} WHERE ${column} = '" + value + "'"\n    return db.query(sql)\n`);
            } else if (table === 'stock' && i === 2) {
              fns.push(`def ${name}():\n    # fixed list of columns, safe to format\n    order = SORTS.get(request.args.get("sort"), "created_at")\n    return db.query(f"SELECT * FROM ${table} ORDER BY {order} DESC LIMIT 50")\n`);
            } else {
              fns.push(`def ${name}():\n    value = ${source}\n    return db.query("SELECT * FROM ${table} WHERE ${column} = ?", (value,))\n`);
            }
            n++;
          }
          files[`/home/learner/inventory/${table}.py`] = `from flask import request\nimport db\n\nSORTS = {"date": "created_at", "name": "name"}\n\n${fns.join('\n')}`;
        }
        files['/home/learner/inventory/db.py'] = 'def query(sql, params=()):\n    ...\n';
        return { type: 'shell', cwd: '/home/learner/inventory', motd: `Inventory service source: ${n} query functions in /home/learner/inventory\n`, files };
      },
      hints: ['Start from the sink: every database call goes through `db.query`. Look at how the SQL text is built for each one.', 'Parameterised calls pass values separately, with a `?` in the SQL. Search for SQL built with `+` or f-strings instead.', '`grep -rn "+ value\\|f\\"SELECT" .` then read the function each hit belongs to. One of the f-strings is safe; check where its value comes from.'],
      writeup: {
        how: 'All but two functions pass values as parameters. `grep -rn \'f"SELECT\\|" +\' .` finds the other two. In `stock.py`, the f-string inserts `order`, which comes from the fixed `SORTS` dictionary, so the user can only choose between known column names: safe. In `suppliers.py`, the query is built by concatenating `value`, taken straight from the request, into the SQL text. That function is the injectable one.',
        why: 'Searching from sinks finds candidates fast, but the reviewer still has to trace each one back to its source. Flagging every f-string would have wasted the developers\' time on a safe function, and missing the concatenated one would have left the real hole open.',
        fix: 'Rewrite the function with a parameter: `db.query("SELECT * FROM suppliers WHERE name = ?", (value,))`. Add a linting rule (for example a Semgrep rule) that flags SQL built with string concatenation or formatting.'
      }
    },
    {
      id: 'code-secret',
      title: 'Still in the repository',
      difficulty: 'easy',
      points: 100,
      skills: ['grep -rn', 'secrets', 'hidden files'],
      prepare: ['code-secrets'],
      brief: 'A cloud provider emailed Larkfield: one of its access keys was used from an unknown network last night. The key starts with `LKIA`. The platform team says keys are never stored in code. You have a copy of the deployment repository, including the parts most people never look at.',
      goal: 'Find where the key starting with `LKIA` is stored in the repository and submit its location as `HW{path:line}`, using the path relative to the repository root, for example `HW{src/app.py:12}`.',
      flag: 'C4/IGMM3Vy3q+zK8RCCrFGD+Tb/W95rF9tHE4CG6',
      workspace: () => {
        const r = random(77);
        const files = {};
        const base = '/home/learner/deploy';
        const fill = (n) => Array.from({ length: n }, () => r.pick(['# deploy settings', 'replicas: 2', 'region: eu-west-2', 'timeout: 30', 'retries: 3', 'log_level: info'])).join('\n');
        files[`${base}/README.md`] = 'Deployment configuration for Larkfield services.\n';
        files[`${base}/services/shop.yaml`] = `${fill(10)}\nimage: shop:2.3.1\n`;
        files[`${base}/services/api.yaml`] = `${fill(14)}\naccess_key_id: \${VAULT_KEY_ID}\n`;
        files[`${base}/services/reports.yaml`] = `${fill(8)}\n# example only, not a real key\naccess_key_id: LKIAEXAMPLEEXAMPLE00\n`;
        files[`${base}/.ci/old/release.env.bak`] = `${fill(11).replace(/: /g, '=')}\nCLOUD_ACCESS_KEY_ID=LKIA4Q7XRM2ZT8VBN5JD\nCLOUD_SECRET_ACCESS_KEY=Zq8r1Lw0pNfXcV3e9TbYh2uKs6DmAo7Gj4WiEy5R\n${fill(3).replace(/: /g, '=')}\n`;
        files[`${base}/scripts/rotate.sh`] = '#!/bin/sh\n# rotates keys via the vault, never writes them to disk\nvault write -f cloud/rotate\n';
        return { type: 'shell', cwd: base, motd: 'Deployment repository at ~/deploy\n', files };
      },
      hints: ['grep can search a whole folder tree and show line numbers. Hidden folders are searched too.', '`grep -rn "LKIA" .` lists every match with its file and line number.', 'One match is clearly marked as an example and is not a real key format. Use the other one, and give its path without the leading `./`.'],
      writeup: {
        how: '`grep -rn "LKIA" .` finds two matches. `services/reports.yaml` contains `LKIAEXAMPLEEXAMPLE00`, clearly a documentation placeholder. The real key is in `.ci/old/release.env.bak` on line 12, along with its secret: an old CI environment file kept as a backup in a hidden folder. `ls` without `-a` would not even show the `.ci` folder.',
        why: 'Secrets tend to survive in backups, old CI configuration and hidden folders long after the "real" configuration has moved to a vault. Attackers who get read access to a repository search it exactly like this. "We never store keys in code" is a policy; the repository is the evidence.',
        fix: 'Rotate the key immediately and review the provider\'s logs for what the old key did. Remove the file, consider rewriting history, add secret scanning to CI and pre-commit hooks, and restrict what that key could do.'
      }
    },
    {
      id: 'code-idor',
      title: 'Whose invoice is it?',
      difficulty: 'medium',
      points: 150,
      skills: ['access control', 'IDOR', 'code reading'],
      prepare: ['code-access'],
      brief: 'The customer portal lets people view and download their invoices. A customer reported that changing a number in the address bar showed them someone else\'s invoice. The portal has six routes that take an ID, and the developers believe they all check ownership.',
      goal: 'Find the route handler that returns data for an ID without checking it belongs to the current customer, and submit its function name as `HW{function}`.',
      flag: 'a4iwgO7zZQyAxNMFgvRgscLPfPagpiNz',
      workspace: () => ({
        type: 'shell',
        cwd: '/home/learner/portal',
        motd: 'Customer portal source in ~/portal\n',
        files: {
          '/home/learner/portal/auth.py': `from functools import wraps
from flask import session, abort

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "customer_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapper

def owns(record):
    return record is not None and record["customer_id"] == session["customer_id"]
`,
          '/home/learner/portal/invoices.py': `from flask import Blueprint, abort, session, send_file
from auth import login_required, owns
import db

bp = Blueprint("invoices", __name__)

@bp.get("/invoices/<int:invoice_id>")
@login_required
def view_invoice(invoice_id):
    invoice = db.get_invoice(invoice_id)
    if not owns(invoice):
        abort(404)
    return invoice

@bp.get("/invoices/<int:invoice_id>/pdf")
@login_required
def download_invoice_pdf(invoice_id):
    invoice = db.get_invoice(invoice_id)
    if invoice is None:
        abort(404)
    return send_file(invoice["pdf_path"])

@bp.get("/invoices")
@login_required
def list_invoices():
    return {"invoices": db.invoices_for(session["customer_id"])}
`,
          '/home/learner/portal/orders.py': `from flask import Blueprint, abort, session
from auth import login_required, owns
import db

bp = Blueprint("orders", __name__)

@bp.get("/orders/<int:order_id>")
@login_required
def view_order(order_id):
    order = db.get_order(order_id)
    if not owns(order):
        abort(404)
    return order

@bp.post("/orders/<int:order_id>/cancel")
@login_required
def cancel_order(order_id):
    order = db.get_order_for(order_id, session["customer_id"])
    if order is None:
        abort(404)
    db.cancel(order_id)
    return {"cancelled": order_id}
`,
          '/home/learner/portal/addresses.py': `from flask import Blueprint, abort, request
from auth import login_required, owns
import db

bp = Blueprint("addresses", __name__)

@bp.put("/addresses/<int:address_id>")
@login_required
def update_address(address_id):
    address = db.get_address(address_id)
    if not owns(address):
        abort(404)
    db.update_address(address_id, request.json)
    return {"ok": True}

@bp.get("/addresses/<int:address_id>")
@login_required
def view_address(address_id):
    address = db.get_address(address_id)
    if not owns(address):
        abort(403)
    return address
`
        }
      }),
      hints: ['Every route is behind `@login_required`, which only proves someone is logged in. Look for what each handler checks after loading the record.', 'Most handlers call `owns(...)` or load the record together with the customer ID. One handler only checks that the record exists.', 'Read each function that takes an ID. The one that checks `is None` and nothing else is the answer.'],
      writeup: {
        how: 'Every handler requires a login, but that only proves the user is someone. Most then call `owns()` or, like `cancel_order`, query by both ID and customer. `download_invoice_pdf` loads the invoice by ID, checks only that it exists, and sends its PDF. The HTML view of the same invoice is protected, which is why nobody noticed: the developers tested the page they could see.',
        why: 'Broken object level authorisation is the most common serious API flaw. It is invisible in normal use and trivial to exploit by counting through IDs, which is how many large data leaks have happened. Reviewers check every handler that takes an ID, including secondary ones like downloads and exports.',
        fix: 'Add the same `owns(invoice)` check to the PDF route, or better, give the data layer functions that always take the customer ID so it cannot be forgotten. Add a test that requests another customer\'s records for every route.'
      }
    },
    {
      id: 'code-command',
      title: 'Hostnames only',
      difficulty: 'medium',
      points: 200,
      skills: ['command injection', 'subprocess', 'validation'],
      prepare: ['code-injection'],
      brief: 'The network team\'s internal tools app runs diagnostics: ping, traceroute, DNS lookups and a certificate check. Each feature takes a host name from a web form. Some of them were written carefully. The security team wants to know which one can be made to run extra commands.',
      goal: 'Find the function where form input reaches a shell, and submit its name as `HW{function}`.',
      flag: '03fUwvSeCa4cov8TTlDvH/yU',
      workspace: () => ({
        type: 'shell',
        cwd: '/home/learner/netools',
        motd: 'Network tools app source in ~/netools\n',
        files: {
          '/home/learner/netools/validate.py': `import re

HOSTNAME = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

def valid_host(value):
    return bool(HOSTNAME.match(value)) and not value.startswith("-")
`,
          '/home/learner/netools/tools.py': `import subprocess
from flask import request, abort
from validate import valid_host

def run_ping():
    host = request.form["host"]
    if not valid_host(host):
        abort(400)
    return subprocess.run(["ping", "-c", "3", host], capture_output=True, text=True).stdout

def run_traceroute():
    host = request.form["host"]
    if not valid_host(host):
        abort(400)
    return subprocess.run(["traceroute", "-m", "15", host], capture_output=True, text=True).stdout

def run_dig():
    host = request.form["host"]
    record = request.form.get("type", "A")
    if record not in ("A", "AAAA", "MX", "TXT"):
        abort(400)
    return subprocess.run(["dig", "+short", host, record], capture_output=True, text=True).stdout

def run_cert_check():
    host = request.form["host"]
    port = int(request.form.get("port", 443))
    cmd = f"echo | openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -noout -dates"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def run_whois():
    host = request.form["host"]
    if not valid_host(host):
        abort(400)
    return subprocess.check_output(["whois", host], text=True)
`,
          '/home/learner/netools/README.md': 'Diagnostics for the network team. Every tool validates the host name first.\n'
        }
      }),
      hints: ['Look at how each function calls subprocess. A list of arguments never goes through a shell.', 'Search for `shell=True`. Then check whether that function validates its input.', 'One function builds a command string with an f-string, uses `shell=True`, and never calls `valid_host`. The `int()` on the port does not protect the host.'],
      writeup: {
        how: 'Four functions pass a list of arguments to `subprocess.run`, so no shell is involved, and three of them also validate the host. `run_dig` does not validate `host`, which is worth a note (input starting with `-` could become an option), but it still cannot run extra commands. `run_cert_check` builds a single command string with the host inside it and runs it with `shell=True`, because it needs a pipe, and never calls `valid_host`. Shell metacharacters in the host field would run additional commands as the web server user.',
        why: 'The README claims every tool validates its input, and four out of five nearly do. Review means checking each path, because the dangerous one is often the odd one written differently: here, the only tool that needed shell features.',
        fix: 'Validate the host with `valid_host`, and avoid the shell: run `openssl s_client` with a list of arguments and pass its output to the second step in Python, or use Python\'s `ssl` module to fetch the certificate directly. Add `valid_host` to `run_dig` too.'
      }
    },
    {
      id: 'code-path',
      title: 'Just the file name',
      difficulty: 'medium',
      points: 200,
      skills: ['path traversal', 'canonical paths', 'code reading'],
      prepare: ['code-files'],
      brief: 'A document service lets staff download templates, policies, their own reports and shared exports. A web application firewall alert showed requests containing `..%2f` to the service. Four handlers read files based on request input. Find the one that would actually let those requests out of its folder.',
      goal: 'Find the handler that can read files outside its intended folder and submit its function name as `HW{function}`.',
      flag: 'l9zhV7/LgdvOnFaRuC0=',
      workspace: () => ({
        type: 'shell',
        cwd: '/home/learner/docservice',
        motd: 'Document service source in ~/docservice\n',
        files: {
          '/home/learner/docservice/handlers.py': `import os
from flask import request, send_from_directory, send_file, abort, session
import db

TEMPLATES = "/srv/docs/templates"
POLICIES = "/srv/docs/policies"
REPORTS = "/srv/docs/reports"
EXPORTS = "/srv/docs/exports"

def get_template():
    return send_from_directory(TEMPLATES, request.args["name"])

def get_policy():
    name = os.path.basename(request.args["name"])
    return send_file(os.path.join(POLICIES, name))

def get_report():
    report = db.report_for(request.args["id"], session["user_id"])
    if report is None:
        abort(404)
    return send_file(os.path.join(REPORTS, report["filename"]))

def get_export():
    name = request.args["name"].replace("../", "")
    path = os.path.join(EXPORTS, name)
    if not path.endswith(".csv"):
        abort(400)
    return send_file(path)
`,
          '/home/learner/docservice/notes.md': 'Reports are looked up by ID and owner, so users never send file names for those.\n'
        }
      }),
      hints: ['For each handler, ask: what is the final path made of, and which part comes from the user?', '`send_from_directory` resolves and checks the path for you. `os.path.basename` throws away every folder part. Report names come from the database, not the request.', 'The handler that tries to clean input by removing `../` once and checks only the extension is the vulnerable one. Think about `....//` and absolute paths.'],
      writeup: {
        how: '`get_template` uses `send_from_directory`, which refuses paths that resolve outside the folder. `get_policy` keeps only the base name, so no folder parts survive. `get_report` takes a file name from the database record that belongs to the user, not from the request. `get_export` removes `../` once, which `....//` survives (it becomes `../` after the replacement), and an absolute path such as `/etc/app/secrets.csv` replaces the folder entirely in `os.path.join`. The `.csv` check only limits which files can be read, not where they are.',
        why: 'Filtering bad sequences out of input is a common and fragile approach. The reliable approaches are the ones the other three handlers use: let a tested function do the containment, strip input down to what you need, or do not take file names from users at all.',
        fix: 'Use `send_from_directory(EXPORTS, name)`, or resolve the path with `os.path.realpath` and check it starts with the exports folder plus a path separator. Better still, look exports up by ID like reports.'
      }
    },
    {
      id: 'code-fix',
      title: 'Choose the patch',
      difficulty: 'hard',
      points: 250,
      skills: ['patch review', 'SQL injection', 'allow lists'],
      prepare: ['code-injection'],
      brief: 'The order history endpoint was reported as injectable through both its search box and its sort option. Six developers each sent a patch. Some fix one problem and not the other, some introduce new problems, and one is right.\n\nThe original code is in `history.py` and the patches are in `patches/`.',
      goal: 'Review the patches and submit the file name of the one that fixes both problems correctly, including `.diff`, as `HW{name}`.',
      flag: 'Qy54Ksdr9sqSNbCHvSZpj7zbjBTVhK3L+uJRcrWftRdiDzB6fQg=',
      workspace: () => {
        const original = `def order_history():
    term = request.args.get("q", "")
    sort = request.args.get("sort", "created_at")
    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session['uid']} AND note LIKE '%{term}%' ORDER BY {sort}"
    return db.query(sql)
`;
        const patches = {
          '0001-escape-quotes.diff': ['-    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"', '+    term = term.replace("\'", "\'\'")', '+    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"'],
          '0002-parameters.diff': ['-    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"', '-    return db.query(sql)', '+    sql = f"SELECT id, total, note FROM orders WHERE user_id = ? AND note LIKE ? ORDER BY {sort}"', '+    return db.query(sql, (session["uid"], f"%{term}%"))'],
          '0003-parameters-sort-param.diff': ['-    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"', '-    return db.query(sql)', '+    sql = "SELECT id, total, note FROM orders WHERE user_id = ? AND note LIKE ? ORDER BY ?"', '+    return db.query(sql, (session["uid"], f"%{term}%", sort))'],
          '0004-allowlist-and-parameters.diff': ['+SORTS = {"created_at": "created_at", "total": "total", "id": "id"}', '+', '-    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"', '-    return db.query(sql)', '+    column = SORTS.get(sort, "created_at")', '+    sql = f"SELECT id, total, note FROM orders WHERE user_id = ? AND note LIKE ? ORDER BY {column}"', '+    return db.query(sql, (session["uid"], f"%{term}%"))'],
          '0005-regex-block.diff': ['+BAD = re.compile(r"(union|select|--|;|\')", re.I)', '+', '+    if BAD.search(term) or BAD.search(sort):', '+        abort(400)'],
          '0006-allowlist-no-user.diff': ['+SORTS = {"created_at": "created_at", "total": "total", "id": "id"}', '+', '-    sql = f"SELECT id, total, note FROM orders WHERE user_id = {session[\'uid\']} AND note LIKE \'%{term}%\' ORDER BY {sort}"', '-    return db.query(sql)', '+    column = SORTS.get(sort, "created_at")', '+    sql = f"SELECT id, total, note FROM orders WHERE note LIKE ? ORDER BY {column}"', '+    return db.query(sql, (f"%{term}%",))']
        };
        const files = { '/home/learner/review/history.py': original };
        for (const [name, lines] of Object.entries(patches)) {
          files[`/home/learner/review/patches/${name}`] = `--- a/history.py\n+++ b/history.py\n@@ -1,5 +1,7 @@\n def order_history():\n     term = request.args.get("q", "")\n     sort = request.args.get("sort", "created_at")\n${lines.join('\n')}\n`;
        }
        return { type: 'shell', cwd: '/home/learner/review', motd: 'Original code: history.py. Proposed patches: patches/\n', files };
      },
      hints: ['There are two inputs, `q` and `sort`, and they need different fixes. A value can be a parameter. A column name cannot.', 'Lines starting with `-` are removed and lines with `+` are added. Check each patch for: values passed as parameters, the sort column chosen from a fixed list, and the query still limited to the current user.', 'Patch 0003 passes the column name as a parameter, which databases do not support the way it intends. Patch 0006 drops the user filter. Only one patch gets all three right.'],
      writeup: {
        how: 'Patch 0001 escapes quotes in `term` but leaves `sort` injectable. 0002 parameterises the values but still formats `sort` into the SQL. 0003 passes the sort column as a parameter, which makes the database sort by a constant string rather than the column, so sorting silently breaks. 0005 is a block list that misses many injections and rejects legitimate searches containing an apostrophe. 0006 uses an allow list and parameters but removes `user_id = ?`, so every customer sees everyone\'s orders. `0004-allowlist-and-parameters.diff` parameterises both values, chooses the column from a fixed dictionary, and keeps the user filter.',
        why: 'Reviewing a fix is as important as finding the bug. Partial fixes are common, and a patch that fixes the reported issue while introducing an access control flaw, like 0006, can be worse than the original. The right fix uses parameters for values and an allow list for identifiers.',
        fix: 'Merge 0004, add tests that send quotes and SQL keywords in both parameters and check the results stay limited to the current user, and add a lint rule against formatting SQL strings.'
      }
    }
  ]
};
