import sqlite3, os
DB = os.path.join(os.path.dirname(__file__), "..", "database.db")
con = sqlite3.connect(DB)
cur = con.cursor()
# check if scanned_at exists
cur.execute("PRAGMA table_info(scans)")
cols = [r[1] for r in cur.fetchall()]
if "scanned_at" not in cols:
    cur.execute("ALTER TABLE scans ADD COLUMN scanned_at TEXT")
    print("Added scanned_at column")
else:
    print("scanned_at already exists")
con.commit()
con.close()
