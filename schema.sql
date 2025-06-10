CREATE TABLE IF NOT EXISTS users (
    id char(36) PRIMARY KEY DEFAULT(UUID()),
    username VARCHAR(20) NOT NUL,
    email VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_otp VARCHAR(5),
    otp_exp TIMESTAMP null,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

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
    INDEX idx_user_id (user_id),
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;