// Run with Node.js 24 or newer: node quest-demo.js
// Open http://127.0.0.1:3019/ in a browser.
const { createServer } = require('node:http');
const { randomBytes, scryptSync, timingSafeEqual } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { join } = require('node:path');

const host = '127.0.0.1';
const port = Number(process.env.QUEST_PORT || 3019);
const origin = 'http://' + host + ':' + port;
const db = new DatabaseSync(process.env.QUEST_DB || join(__dirname, 'quest-demo.sqlite'));
db.exec(`CREATE TABLE IF NOT EXISTS players (
  username TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  password_hash BLOB NOT NULL,
  checkpoint INTEGER NOT NULL DEFAULT 1
)`);

const sessions = new Map();
const checkpoints = ['The trailhead', 'The old bridge', 'The final gate'];

function render(res, player, message = '') {
  // Usernames are limited to ASCII letters, digits, underscores and hyphens.
  const content = player
    ? `<p>Signed in as <strong>${player.username}</strong></p>
      <h2>Checkpoint ${player.checkpoint} of ${checkpoints.length}</h2>
      <p>${checkpoints[player.checkpoint - 1]}</p>
      ${player.checkpoint < checkpoints.length
        ? '<form method="post" action="/advance"><button>Save and advance</button></form>'
        : '<p>Quest complete.</p>'}
      <form method="post" action="/logout"><button>Sign out</button></form>`
    : `<p>Create a test account or sign in to resume.</p>
      <form method="post">
        <label>Username <input name="username" autocomplete="username" required maxlength="24" pattern="[A-Za-z0-9_\\-]{1,24}"></label>
        <label>Password <input name="password" type="password" required maxlength="128"></label>
        <button formaction="/login">Sign in</button>
        <button formaction="/register">Create account</button>
      </form>`;
  res.writeHead(message ? 400 : 200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quest demo</title>
<style>
  body { max-width: 32rem; margin: 3rem auto; padding: 0 1rem; font: 1rem/1.5 system-ui; }
  label, input { display: block; }
  input, button { font: inherit; padding: .45rem; }
  input { margin-bottom: 1rem; max-width: 100%; }
  form { margin-top: 1rem; }
</style>
<main><h1>Quest demo</h1>${message ? '<p role="alert">' + message + '</p>' : ''}${content}</main>
</html>`);
}

function redirect(res, token) {
  const cookie = 'quest_session=' + token + '; Path=/; HttpOnly; SameSite=Strict';
  res.writeHead(303, {
    Location: '/',
    'Set-Cookie': token ? cookie : cookie + '; Max-Age=0',
  }).end();
}

async function handle(req, res) {
  if (req.headers.host !== host + ':' + port) {
    return res.writeHead(400).end();
  }

  const token = (req.headers.cookie || '').match(/(?:^|; *)quest_session=([a-f0-9]{64})(?:;|$)/)?.[1];
  const username = sessions.get(token);
  const player = username && db.prepare('SELECT username, checkpoint FROM players WHERE username = ?').get(username);

  if (req.method === 'GET' && req.url === '/') return render(res, player);
  if (req.method !== 'POST') return res.writeHead(404).end();
  if (req.headers.origin && req.headers.origin !== origin) return res.writeHead(403).end();

  if (req.url === '/logout') {
    sessions.delete(token);
    return redirect(res, '');
  }

  if (req.url === '/advance') {
    if (player) {
      db.prepare('UPDATE players SET checkpoint = checkpoint + 1 WHERE username = ? AND checkpoint < ?')
        .run(username, checkpoints.length);
    }
    return redirect(res, player ? token : '');
  }

  if (req.url !== '/login' && req.url !== '/register') return res.writeHead(404).end();

  const chunks = [];
  let size = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > 4096) return res.writeHead(413, { Connection: 'close' }).end();
    chunks.push(chunk);
  }
  const fields = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
  const name = (fields.get('username') || '').trim().toLowerCase();
  const password = fields.get('password') || '';
  if (!/^[a-z0-9_-]{1,24}$/.test(name) || password.length < 1 || password.length > 128) {
    return render(res, player, 'Use 1–24 letters, digits, underscores or hyphens for your username and enter a password.');
  }

  const account = db.prepare('SELECT salt, password_hash FROM players WHERE username = ?').get(name);
  if (req.url === '/register') {
    if (account) return render(res, player, 'That username is taken.');
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64);
    db.prepare('INSERT INTO players (username, salt, password_hash) VALUES (?, ?, ?)').run(name, salt, hash);
  } else if (!account || !timingSafeEqual(scryptSync(password, account.salt, 64), account.password_hash)) {
    return render(res, player, 'That username or password is incorrect.');
  }

  sessions.delete(token);
  const newToken = randomBytes(32).toString('hex');
  sessions.set(newToken, name);
  redirect(res, newToken);
}

createServer((req, res) => {
  handle(req, res).catch(error => {
    console.error(error);
    if (!res.headersSent) res.writeHead(500).end('The quest could not save your request.');
    else res.end();
  });
}).listen(port, host, () => console.log('Quest demo running at ' + origin + '/'));
