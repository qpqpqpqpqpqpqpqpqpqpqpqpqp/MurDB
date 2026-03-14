import argparse
from pathlib import Path

def main(out: str):
    Path(out).write_bytes(b'not a sqlite database')
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='bad.db')
    args = parser.parse_args()
    main(args.out)
