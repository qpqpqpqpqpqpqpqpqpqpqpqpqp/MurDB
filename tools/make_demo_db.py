import argparse
import sqlite3

def main(out: str):
    con = sqlite3.connect(out)
    cur = con.cursor()
    cur.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, api_token TEXT)')
    cur.executemany('INSERT INTO users(email, api_token) VALUES (?, ?)', [(f'user{index}@example.com', f'tok_live_demo_{index:04d}_secret') for index in range(1, 121)])
    cur.execute('CREATE TABLE audit(id INTEGER PRIMARY KEY, action TEXT)')
    cur.executemany('INSERT INTO audit(action) VALUES (?)', [('login',), ('logout',), ('upload',), ('download',)] * 30)
    con.commit()
    con.close()
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='demo.db')
    args = parser.parse_args()
    main(args.out)
