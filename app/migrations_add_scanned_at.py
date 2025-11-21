# app/migrations_add_scanned_at.py
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "database.db"))

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table});")
    cols = [row[1] for row in cur.fetchall()]  # row[1] is column name
    return column in cols

def add_scanned_at():
    conn = sqlite3.connect(DB_PATH)
    try:
        if not column_exists(conn, "scans", "scanned_at"):
            print("Adding scanned_at column to scans table...")
            conn.execute("ALTER TABLE scans ADD COLUMN scanned_at TEXT;")
            conn.commit()
            print("scanned_at column added.")
        else:
            print("scanned_at already exists — nothing to do.")
    finally:
        conn.close()

if __name__ == "__main__":
    add_scanned_at()
