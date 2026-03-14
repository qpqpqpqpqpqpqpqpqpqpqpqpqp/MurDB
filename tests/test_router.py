import unittest
from murdb_core.router import decide_target_prefix

class RouterTests(unittest.TestCase):

    def test_low_risk_approved_goes_to_main_backups(self):
        result = {'risk_level': 'LOW', 'decision': 'approved', 'explanation': 'ok', 'recommendations': []}
        self.assertEqual(decide_target_prefix(result), 'main-backups')

    def test_high_risk_goes_to_quarantine(self):
        result = {'risk_level': 'HIGH', 'decision': 'approved', 'explanation': 'bad', 'recommendations': ['review']}
        self.assertEqual(decide_target_prefix(result), 'quarantine')
