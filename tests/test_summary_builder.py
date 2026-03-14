import tempfile
import unittest
from pathlib import Path
from murdb_core.summary_builder import build_sqlite_summary
from tools.make_bad_db import main as make_bad_db
from tools.make_clean_db import main as make_clean_db
from tools.make_demo_db import main as make_demo_db
from tools.make_rare_db import main as make_rare_db

class SummaryBuilderTests(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_clean_db_has_no_suspicious_fields(self):
        db_path = self.base / 'clean.db'
        make_clean_db(str(db_path))
        summary = build_sqlite_summary(str(db_path))
        self.assertFalse(summary['global_observations']['contains_suspicious_fields'])
        self.assertEqual(summary['suspicious_fields'], [])

    def test_demo_db_contains_sensitive_indicators(self):
        db_path = self.base / 'demo.db'
        make_demo_db(str(db_path))
        summary = build_sqlite_summary(str(db_path))
        columns = {(item['table'], item['column']) for item in summary['suspicious_fields']}
        self.assertIn(('users', 'email'), columns)
        self.assertIn(('users', 'api_token'), columns)

    def test_rare_db_detects_deep_row_indicator(self):
        db_path = self.base / 'rare.db'
        make_rare_db(str(db_path))
        summary = build_sqlite_summary(str(db_path))
        columns = {(item['table'], item['column']) for item in summary['suspicious_fields']}
        self.assertIn(('archive_d', 'note'), columns)

    def test_bad_db_is_rejected(self):
        db_path = self.base / 'bad.db'
        make_bad_db(str(db_path))
        with self.assertRaises(ValueError):
            build_sqlite_summary(str(db_path))
