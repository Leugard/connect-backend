CREATE TABLE IF NOT EXISTS stories (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    media_url TEXT NOT NULL,
    caption TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);