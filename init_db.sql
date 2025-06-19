CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  login VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  is_admin BOOLEAN DEFAULT false,
  subscription_active BOOLEAN DEFAULT false
);

-- Додайте ваш адмінський акаунт
INSERT INTO users (login, password_hash, is_admin, subscription_active)
VALUES ('yokoko', '$2b$10$ваш_хеш_пароля', true, true);
