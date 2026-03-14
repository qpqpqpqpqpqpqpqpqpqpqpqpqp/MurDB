import argparse
import sqlite3

def main(out: str):
    con = sqlite3.connect(out)
    cur = con.cursor()
    cur.execute('CREATE TABLE archive_a(id INTEGER PRIMARY KEY, username TEXT, note TEXT)')
    cur.execute('CREATE TABLE archive_b(id INTEGER PRIMARY KEY, code TEXT, value TEXT)')
    cur.execute('CREATE TABLE archive_c(id INTEGER PRIMARY KEY, owner TEXT, status TEXT)')
    cur.execute('CREATE TABLE archive_d(id INTEGER PRIMARY KEY, username TEXT, note TEXT)')
    cur.executemany('INSERT INTO archive_a(id, username, note) VALUES (?, ?, ?)', [(index, f'user_a_{index}', 'normal') for index in range(1, 231)])
    cur.executemany('INSERT INTO archive_b(id, code, value) VALUES (?, ?, ?)', [(index, f'B{index:03d}', 'ok') for index in range(1, 231)])
    cur.executemany('INSERT INTO archive_c(id, owner, status) VALUES (?, ?, ?)', [(index, f'owner_{index}', 'archived') for index in range(1, 231)])
    rows_d = [(index, f'user_d_{index}', 'normal') for index in range(1, 230)]
    rows_d.append((230, 'admin', 'contains password reset token for manual review'))
    cur.executemany('INSERT INTO archive_d(id, username, note) VALUES (?, ?, ?)', rows_d)
    con.commit()
    con.close()
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='rare.db')
    args = parser.parse_args()
    main(args.out)
