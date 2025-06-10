CREATE TABLE IF NOT EXISTS verification_tokens (
    id CHAR(36) PRIMARY KEY DEFAULT(UUID()),
    user_id CHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL,
    type ENUM(
        'email_verification',
        'password_reset'
    ) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_id (user_id)
);