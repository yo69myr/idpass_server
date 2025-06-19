require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middleware для перевірки авторизації
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Реєстрація нового користувача
app.post('/api/register', async (req, res) => {
  try {
    const { login, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Перевірка, чи існує вже такий логін
    const checkUser = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ status: 'error', message: 'Користувач з таким логіном вже існує' });
    }
    
    // Додавання адміна (вашого акаунту)
    const isAdmin = login === 'yokoko';
    
    const result = await pool.query(
      'INSERT INTO users (login, password_hash, created_at, is_admin, subscription_active) VALUES ($1, $2, NOW(), $3, true) RETURNING *',
      [login, hashedPassword, isAdmin]
    );
    
    res.json({ status: 'success', user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Помилка сервера' });
  }
});

// Логін
app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ status: 'error', message: 'Невірний логін або пароль' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ status: 'error', message: 'Невірний логін або пароль' });
    }
    
    const token = jwt.sign(
      { id: user.id, login: user.login, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      status: 'success',
      token,
      login: user.login,
      created_at: user.created_at,
      is_admin: user.is_admin,
      subscription_active: user.subscription_active
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Помилка сервера' });
  }
});

// Адмін-панель (отримання всіх користувачів)
app.post('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ status: 'error', message: 'Доступ заборонено' });
    }
    
    const { login, password } = req.body;
    const admin = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    
    if (admin.rows.length === 0 || !(await bcrypt.compare(password, admin.rows[0].password_hash))) {
      return res.status(401).json({ status: 'error', message: 'Невірний логін або пароль' });
    }
    
    const users = await pool.query('SELECT login, created_at, password_hash, subscription_active FROM users');
    res.json({ status: 'success', users: users.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Помилка сервера' });
  }
});

// Оновлення підписки
app.post('/api/admin/update_subscription', authenticateToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ status: 'error', message: 'Доступ заборонено' });
    }
    
    const { user_login, subscription_active } = req.body;
    await pool.query(
      'UPDATE users SET subscription_active = $1 WHERE login = $2',
      [subscription_active, user_login]
    );
    
    res.json({ status: 'success' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Помилка сервера' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущено на порті ${PORT}`);
});
