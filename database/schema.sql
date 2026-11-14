-- WebShield main database schema (SQLite)
-- Passwords are NEVER stored in plaintext: only salted hashes produced by the
-- application layer (werkzeug.security / scrypt or PBKDF2).

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS file_scans;
DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE
                          CHECK (length(username) BETWEEN 3 AND 30),
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    content    TEXT    NOT NULL CHECK (length(content) <= 5000),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE comments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER NOT NULL,
    user_id         INTEGER NOT NULL,
    comment_content TEXT    NOT NULL
                            CHECK (length(comment_content) BETWEEN 1 AND 500),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE activity_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    implementation  TEXT NOT NULL DEFAULT 'application'
                         CHECK (implementation IN ('vulnerable', 'secure', 'application')),
    description     TEXT NOT NULL CHECK (length(description) <= 500),
    security_status TEXT NOT NULL
                         CHECK (security_status IN ('EXPLOITED', 'BLOCKED', 'DETECTED', 'NORMAL', 'INFO')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Trojan Horse Defence: one row per scanned upload. The file content itself is
-- never stored - only its metadata, SHA-256 and the scanner verdict.
CREATE TABLE IF NOT EXISTS file_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    filename      TEXT    NOT NULL CHECK (length(filename) <= 255),
    size          INTEGER NOT NULL CHECK (size >= 0),
    sha256        TEXT    NOT NULL CHECK (length(sha256) = 64),
    detected_type TEXT    NOT NULL,
    verdict       TEXT    NOT NULL CHECK (verdict IN ('ACCEPTED', 'SUSPICIOUS', 'BLOCKED')),
    reasons       TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_comments_post ON comments (post_id);
CREATE INDEX idx_logs_created ON activity_logs (created_at);
