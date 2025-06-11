CREATE TABLE IF NOT EXISTS friend_requests (
    id CHAR(36) PRIMARY KEY,
    sender_id CHAR(36) NOT NULL,
    receiver_id CHAR(36) NOT NULL,
    status ENUM(
        'pending',
        'accepted',
        'rejected'
    ) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE (sender_id, receiver_id)
);