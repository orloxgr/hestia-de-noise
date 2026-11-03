import configparser
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import wordpress


@unittest.skipUnless(importlib.util.find_spec('fail2ban'), 'Native Fail2ban evaluator')
class Fail2banDurations(unittest.TestCase):
    def test_non_whitelisted_first_duration_reaches_exact_sqlite_permanent_sentinel(self):
        from fail2ban.server.jail import Jail
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            rendered=wordpress.render({**wordpress.DEFAULT,'durations':[4020,259200,-1]},Path(folder))
            text=next(value.decode() for path,value in rendered.items() if path.name=='wordpress-login.local')
            parser=configparser.ConfigParser(interpolation=None);parser.read_string(text)
            values=parser[wordpress.JAIL]
            jail=Jail('hdn-proof',backend='polling')
            jail.setBanTimeExtra('factor',values['bantime.factor'])
            jail.setBanTimeExtra('multipliers',values['bantime.multipliers'])
            evaluate=jail.getBanTimeExtra()['evformula']
            db=sqlite3.connect(':memory:');self.addCleanup(db.close)
            db.execute('CREATE TABLE proof (bantime INTEGER)')
            expected=[4020,259200,-1,-1]
            for count,target in enumerate(expected):
                duration=evaluate(SimpleNamespace(Time=4020,Count=count))
                self.assertIs(type(duration),int)
                self.assertEqual(duration,target)
                db.execute('INSERT INTO proof VALUES (?)',(duration,))
            self.assertEqual([row[0] for row in db.execute('SELECT * FROM proof')],expected)
