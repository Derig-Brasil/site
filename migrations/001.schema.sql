-- Users
CREATE TABLE IF NOT EXISTS users (
  id CHAR(26) PRIMARY KEY CHECK (length(id) = 26), -- ULID
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash CHAR(43) NOT NULL,                 -- base64url(SHA-256)
  salt CHAR(22) NOT NULL,                          -- base64url(16 bytes)
  created_at CHAR(24) NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  email_verified_at CHAR(24),
  is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- User profile data
CREATE TABLE IF NOT EXISTS user_profiles (
  email VARCHAR(100) PRIMARY KEY,
  name VARCHAR(50),
  last_name VARCHAR(50),
  company VARCHAR(100),
  phone CHAR(15),
  cro CHAR(6),
  cro_uf CHAR(2),
  specialty VARCHAR(64),
  FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_resets (
  id CHAR(26) PRIMARY KEY CHECK (length(id) = 26), -- ULID
  user_id CHAR(26) NOT NULL CHECK (length(user_id) = 26),
  token CHAR(43) NOT NULL CHECK (length(token) = 43), -- base64url(32 bytes)
  created_at CHAR(24) NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at CHAR(24) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);

-- Email verification codes
CREATE TABLE IF NOT EXISTS email_verifications (
  id CHAR(26) PRIMARY KEY CHECK (length(id) = 26), -- ULID
  user_id CHAR(26) NOT NULL CHECK (length(user_id) = 26),
  code CHAR(6) NOT NULL CHECK (length(code) = 6),
  created_at CHAR(24) NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at CHAR(24) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id);