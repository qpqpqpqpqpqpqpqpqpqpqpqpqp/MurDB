import argparse
import sqlite3

def main(out: str):
    con = sqlite3.connect(out)
    cur = con.cursor()
    cur.execute('CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL)')
    cur.executemany('INSERT INTO products(name, price) VALUES (?, ?)', [(f'product_{index}', round(10 + index * 0.25, 2)) for index in range(1, 121)])
    cur.execute('CREATE TABLE metrics(id INTEGER PRIMARY KEY, score INTEGER, checksum INTEGER)')
    cur.executemany('INSERT INTO metrics(score, checksum) VALUES (?, ?)', [(index % 10, 100000 + index) for index in range(1, 121)])
    con.commit()
    con.close()
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='clean.db')
    args = parser.parse_args()
    main(args.out)
