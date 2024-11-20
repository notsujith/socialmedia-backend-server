DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users (
    first_name TEXT, 
    last_name TEXT,
    username TEXT, 
    email_address TEXT,
    hashed_pass TEXT,  
    salt TEXT,
    moderator INTEGER,
    PRIMARY KEY (username, email_address),
    UNIQUE (username)
);

DROP TABLE IF EXISTS passwords;
CREATE TABLE IF NOT EXISTS passwords(
    user_name TEXT PRIMARY KEY,
    previous_hashed_pass TEXT,
    FOREIGN KEY (user_name) REFERENCES users(username)
        ON DELETE CASCADE ON UPDATE CASCADE
);

DROP TABLE IF EXISTS posts;
CREATE TABLE IF NOT EXISTS posts(
    title TEXT,
    body TEXT,
    post_id INTEGER PRIMARY KEY,
    owner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner) REFERENCES users(username)
        ON DELETE CASCADE ON UPDATE CASCADE
);

DROP TABLE IF EXISTS tags;
CREATE TABLE IF NOT EXISTS tags(
    post_id INTEGER,
    tags TEXT,
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS follows (
    follower_username TEXT NOT NULL,
    followed_username TEXT NOT NULL,
    PRIMARY KEY (follower_username, followed_username),
    FOREIGN KEY (follower_username) REFERENCES users(username)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (followed_username) REFERENCES users(username)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (post_id, username),
    FOREIGN KEY (post_id) REFERENCES posts(post_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (username) REFERENCES users(username)
        ON DELETE CASCADE ON UPDATE CASCADE
);