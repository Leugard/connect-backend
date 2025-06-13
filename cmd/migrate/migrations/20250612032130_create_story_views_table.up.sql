CREATE TABLE IF NOT EXISTS story_views (
    story_id CHAR(36) NOT NULL,
    viewer_id CHAR(36) NOT NULL,
    viewed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (story_id, viewer_id),
    FOREIGN KEY (story_id) REFERENCES stories (id) ON DELETE CASCADE,
    FOREIGN KEY (viewer_id) REFERENCES users (id) ON DELETE CASCADE
);