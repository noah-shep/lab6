CREATE TABLE IF NOT EXISTS user_report (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    time_entry TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    text TEXT,
    filename TEXT
);
