CREATE TABLE IF NOT EXISTS friends (
    user_id CHAR(36),
    friend_id CHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, friend_id)
);