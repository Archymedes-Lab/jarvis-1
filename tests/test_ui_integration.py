"""Integration invariants independent of redesign layout and detector wording."""
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace

from jarvis.web.server import _indicator_kinds


class IndicatorCountsTests(unittest.TestCase):
    def test_new_request_connection_observes_committed_changes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'counts.db')
            with sqlite3.connect(path) as writer:
                writer.execute('CREATE TABLE indicators (kind TEXT, status TEXT)')
                writer.execute('CREATE INDEX idx_ind_kind ON indicators(kind,status)')
                writer.execute("INSERT INTO indicators VALUES ('ip','active')")
            for expected in (1, 2):
                db = sqlite3.connect(path)
                db.row_factory = sqlite3.Row
                try:
                    counts = _indicator_kinds(SimpleNamespace(db=db))
                    self.assertEqual(counts, {'ip': expected})
                    counts['ip'] = 99
                finally:
                    db.close()
                with sqlite3.connect(path) as writer:
                    writer.execute("INSERT INTO indicators VALUES ('ip','active')")

    def test_older_schema_works_and_database_errors_are_not_cached_as_empty(self):
        db = sqlite3.connect(':memory:')
        db.row_factory = sqlite3.Row
        try:
            db.execute('CREATE TABLE indicators (kind TEXT, status TEXT)')
            db.executemany('INSERT INTO indicators VALUES (?,?)',
                           [('domain', 'active'), ('ip', 'expired')])
            store = SimpleNamespace(db=db)
            self.assertEqual(_indicator_kinds(store), {'domain': 1})
            db.execute('DROP TABLE indicators')
            with self.assertRaises(sqlite3.OperationalError):
                _indicator_kinds(store)
            db.execute('CREATE TABLE indicators (kind TEXT, status TEXT)')
            self.assertEqual(_indicator_kinds(store), {})
        finally:
            db.close()


if __name__ == '__main__':
    unittest.main()
