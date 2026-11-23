import pathlib
import tempfile
import unittest
from unittest.mock import patch

# Patch where each name is looked up: both live in hidden.sockets, and
# rebinding them on the package would not affect the callers.
from jarvis.collectors.process.hidden import sockets


class PortVisibilityTests(unittest.TestCase):
    def test_all_inode_zero_time_wait_ports_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            net = pathlib.Path(directory) / 'net'
            net.mkdir()
            (net / 'tcp').write_text('header\n0: 0100007F:9090 remote 06 0 0 0 0 0 0\n1: 0100007F:9091 remote 06 0 0 0 0 0 0\n')
            with patch.object(sockets, 'PROC', directory):
                self.assertEqual(sockets._visible_tcp_ports(), {0x9090, 0x9091})

    def test_unreadable_table_is_not_empty_clean_table(self):
        with patch.object(sockets, '_visible_tcp_ports', return_value=None):
            with self.assertRaises(RuntimeError):
                sockets.hidden_listeners(1)
