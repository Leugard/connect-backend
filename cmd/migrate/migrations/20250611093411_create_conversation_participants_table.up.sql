CREATE TABLE IF NOT EXISTS conversation_participants (
    conversation_id CHAR(36),
    user_id CHAR(36),
    PRIMARY KEY (conversation_id, user_id),
    FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);