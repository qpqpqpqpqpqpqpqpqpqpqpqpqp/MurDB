import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import local_demo
from tools.make_bad_db import main as make_bad_db
from tools.make_clean_db import main as make_clean_db
from tools.make_demo_db import main as make_demo_db

class LocalDemoTests(unittest.TestCase):

    def test_process_once_creates_routes_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'workspace'
            incoming = base / 'incoming'
            main_backups = base / 'main-backups'
            quarantine = base / 'quarantine'
            reports = base / 'reports'
            incoming.mkdir(parents=True)
            clean_path = incoming / 'clean.db'
            demo_path = incoming / 'demo.db'
            bad_path = incoming / 'bad.db'
            make_clean_db(str(clean_path))
            make_demo_db(str(demo_path))
            make_bad_db(str(bad_path))

            def fake_analyze(summary, _url):
                if summary['global_observations']['contains_suspicious_fields']:
                    return {'risk_level': 'HIGH', 'decision': 'quarantine', 'explanation': 'suspicious', 'recommendations': ['manual review']}
                return {'risk_level': 'LOW', 'decision': 'approved', 'explanation': 'clean', 'recommendations': ['allow']}
            with patch.object(local_demo, 'BASE', base), patch.object(local_demo, 'INCOMING', incoming), patch.object(local_demo, 'MAIN_BACKUPS', main_backups), patch.object(local_demo, 'QUARANTINE', quarantine), patch.object(local_demo, 'REPORTS', reports), patch.object(local_demo, 'analyze_with_llm', side_effect=fake_analyze):
                local_demo.process_once()
            self.assertTrue((main_backups / 'clean.db').exists())
            self.assertTrue((quarantine / 'demo.db').exists())
            self.assertTrue((reports / 'clean.report.json').exists())
            self.assertTrue((reports / 'bad.error.json').exists())
            clean_report = json.loads((reports / 'clean.report.json').read_text(encoding='utf-8'))
            self.assertEqual(clean_report['route'], 'main-backups')
            self.assertEqual(clean_report['decision'], 'approved')
