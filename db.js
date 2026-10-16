const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('lab2.db');

// Таблица user со структурой id, login, password
db.exec(`
  CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )
`);

// 7 записей (создаются один раз)
const count = db.prepare('SELECT COUNT(*) AS c FROM user').get().c;
if (count === 0) {
  const users = [
    ['admin', 'Admin#2024'],
    ['ivan',  'Ivan_pass1'],
    ['maria', 'Maria_pass2'],
    ['petr',  'Petr_pass3'],
    ['anna',  'Anna_pass4'],
    ['oleg',  'Oleg_pass5'],
    ['olga',  'Olga_pass6'],
  ];
  const insert = db.prepare('INSERT INTO user (login, password) VALUES (?, ?)');
  for (const [login, pass] of users) {
    insert.run(login, bcrypt.hashSync(pass, 10)); // в базе хранится хеш, а не пароль
  }
  console.log('Создано 7 пользователей');
}

module.exports = db;