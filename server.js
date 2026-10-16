const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');

const app = express();

app.use(express.urlencoded({ extended: false })); // чтобы читать данные формы
app.use(session({
  secret: 'lab2-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));
app.use(express.static(path.join(__dirname, 'public'))); // отдаёт login.html

// ---------- Защита страницы: middleware ----------
function requireAuth(req, res, next) {
  if (req.session.userId) return next();   // вошёл — пускаем
  res.redirect('/login.html');             // нет — на форму входа
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

app.get('/', (req, res) => res.redirect('/login.html'));

// ---------- 1) УЯЗВИМЫЙ вход (конкатенация строк) ----------
app.post('/login-vulnerable', (req, res) => {
  const { login, password } = req.body;

  // ПЛОХО: ввод пользователя вставляется прямо в текст SQL
  const sql = `SELECT * FROM user WHERE login = '${login}' AND password = '${password}'`;
  console.log('[VULNERABLE SQL]', sql);

  try {
    const user = db.prepare(sql).get();
    if (user) {
      req.session.userId = user.id;
      req.session.login = user.login;
      return res.redirect('/admin');
    }
    res.redirect('/login.html?error=1');
  } catch (e) {
    res.status(500).send('SQL error: ' + e.message);
  }
});

// ---------- 2) ЗАЩИЩЁННЫЙ вход ----------
const LOGIN_RE = /^[A-Za-z0-9_]{3,20}$/;

app.post('/login', (req, res) => {
  const login = String(req.body.login || '').trim();
  const password = String(req.body.password || '');

  // Server-side валидация (белый список)
  if (!LOGIN_RE.test(login) || password.length < 6 || password.length > 64) {
    return res.redirect('/login.html?error=invalid');
  }

  // Параметризованный запрос: ? — это данные, а не код
  const user = db.prepare('SELECT id, login, password FROM user WHERE login = ?').get(login);

  // Сравнение пароля с хешем; одинаковая ошибка для «нет логина» и «неверный пароль»
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.redirect('/login.html?error=creds');
  }

  req.session.userId = user.id;
  req.session.login = user.login;
  res.redirect('/admin');
});

// ---------- Закрытая страница администратора ----------
app.get('/admin', requireAuth, (req, res) => {
  res.send(`
    <h1>Панель администратора</h1>
    <p>Вы вошли как: <b>${escapeHtml(req.session.login)}</b></p>
    <a href="/logout">Выйти</a>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

app.listen(3000, () => console.log('http://localhost:3000'));