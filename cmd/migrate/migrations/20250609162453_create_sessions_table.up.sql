CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);