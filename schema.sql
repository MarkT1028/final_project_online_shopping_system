DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS orders;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    balance INTEGER DEFAULT 1000000
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    amount INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 預設使用者
INSERT INTO users (username, password_hash) VALUES ('user1', 'hashed_pw_123');