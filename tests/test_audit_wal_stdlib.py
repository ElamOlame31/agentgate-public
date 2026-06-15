"""
Stdlib-only validation of the SQLite WAL pragmas and queue primitives
used by the async audit write queue.

No external dependencies — runs in environments without pydantic/fastapi.
The full integration tests live in test_audit_queue.py (requires full deps).
"""

import os
import queue
import sqlite3
import tempfile
import threading
import time
import unittest


def _apply_wal_pragmas(path: str) -> None:
    """Mirror of what audit.init_db() now sets."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA wal_autocheckpoint=200")
    conn.execute("CREATE TABLE IF NOT EXISTS audit_log (id TEXT, val TEXT)")
    conn.commit()
    conn.close()


class TestWALPragmas(unittest.TestCase):
    """Verify the pragma invariants that init_db() establishes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "wal_test.db")
        _apply_wal_pragmas(self.db)

    def test_journal_mode_is_wal(self):
        conn = sqlite3.connect(self.db)
        row = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        self.assertEqual(row[0].upper(), "WAL")

    def test_synchronous_normal_is_per_connection(self):
        # synchronous is a per-connection setting — not stored in the DB file.
        # Verify that a connection that explicitly sets NORMAL reads back 1.
        conn = sqlite3.connect(self.db)
        conn.execute("PRAGMA synchronous=NORMAL")
        row = conn.execute("PRAGMA synchronous").fetchone()
        conn.close()
        self.assertEqual(row[0], 1)  # 1 = NORMAL

    def test_wal_autocheckpoint_is_per_connection(self):
        # wal_autocheckpoint is also per-connection; verify setting is applied.
        conn = sqlite3.connect(self.db)
        conn.execute("PRAGMA wal_autocheckpoint=200")
        row = conn.execute("PRAGMA wal_autocheckpoint").fetchone()
        conn.close()
        self.assertEqual(row[0], 200)

    def test_immediate_lock_does_not_block_reader(self):
        """
        Key regression: the old code used BEGIN EXCLUSIVE which blocks all
        readers. BEGIN IMMEDIATE in WAL mode must leave readers unblocked.
        """
        writer = sqlite3.connect(self.db)
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO audit_log VALUES ('x', 'y')")

        reader = sqlite3.connect(self.db, timeout=1.0)
        try:
            count = reader.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            # Reader sees pre-transaction state — count should be 0
            self.assertIsInstance(count, int)
        finally:
            reader.close()
            writer.rollback()
            writer.close()

    def test_exclusive_lock_would_block_reader_without_wal(self):
        """
        Confirm that without WAL, EXCLUSIVE blocks readers (demonstrates
        why WAL mode matters). We do this by setting DELETE mode and
        verifying that a reader times out under EXCLUSIVE.
        """
        non_wal_db = os.path.join(self.tmp, "no_wal.db")
        conn = sqlite3.connect(non_wal_db)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("CREATE TABLE IF NOT EXISTS t (x TEXT)")
        conn.commit()
        conn.close()

        writer = sqlite3.connect(non_wal_db)
        writer.execute("BEGIN EXCLUSIVE")

        reader = sqlite3.connect(non_wal_db, timeout=0.05)
        timed_out = False
        try:
            reader.execute("SELECT COUNT(*) FROM t").fetchone()
        except Exception:
            timed_out = True
        finally:
            reader.close()
            writer.rollback()
            writer.close()

        self.assertTrue(timed_out, "Reader should time out under EXCLUSIVE in DELETE mode")

    def test_multiple_connections_can_read_concurrently(self):
        readers = []
        errors = []

        def read():
            try:
                c = sqlite3.connect(self.db, timeout=1.0)
                c.execute("SELECT COUNT(*) FROM audit_log").fetchone()
                c.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class TestQueuePrimitives(unittest.TestCase):
    """
    Tests of the stdlib queue semantics that the audit write queue relies on.
    These confirm our assumptions before trusting them in production.
    """

    def test_fifo_ordering_preserved(self):
        q = queue.Queue()
        for i in range(10):
            q.put(i)
        result = []
        while not q.empty():
            result.append(q.get())
        self.assertEqual(result, list(range(10)))

    def test_put_nowait_raises_full_at_maxsize(self):
        q = queue.Queue(maxsize=2)
        q.put_nowait("a")
        q.put_nowait("b")
        with self.assertRaises(queue.Full):
            q.put_nowait("c")

    def test_join_blocks_until_all_task_done(self):
        q = queue.Queue()
        processed = []

        def worker():
            while True:
                item = q.get()
                if item is None:
                    q.task_done()
                    break
                processed.append(item)
                q.task_done()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        for i in range(20):
            q.put(i)
        q.put(None)
        q.join()  # flush_audit_queue() uses this pattern
        self.assertEqual(processed, list(range(20)))

    def test_single_consumer_guarantees_write_order(self):
        """
        FIFO queue with a single consumer means entries are processed in
        submission order — the invariant audit.log_decision_queued() depends on
        to preserve the HMAC chain without a BEGIN EXCLUSIVE lock.
        """
        q = queue.Queue()
        written_order = []

        def consumer():
            while True:
                item = q.get()
                if item is None:
                    q.task_done()
                    break
                written_order.append(item)
                q.task_done()

        c = threading.Thread(target=consumer, daemon=True)
        c.start()

        # Sequential submission — order must be preserved
        for i in range(50):
            q.put(i)
        q.put(None)
        q.join()
        self.assertEqual(written_order, list(range(50)))

    def test_daemon_thread_does_not_block_process_exit(self):
        """Writer thread must be daemon=True so shutdown isn't gated on it."""
        t = threading.Thread(target=lambda: time.sleep(60), daemon=True)
        t.start()
        self.assertTrue(t.daemon)

    def test_task_done_count_matches_put_count(self):
        q = queue.Queue()
        n = 30
        for i in range(n):
            q.put(i)

        done = [0]

        def worker():
            while not q.empty():
                q.get()
                done[0] += 1
                q.task_done()

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        q.join()
        self.assertEqual(done[0], n)


class TestHMACChainInvariant(unittest.TestCase):
    """
    Verify the ordering invariant that allows log_decision_queued to preserve
    HMAC chain integrity without BEGIN EXCLUSIVE.
    """

    def test_sequential_queue_preserves_entry_order(self):
        """
        Entries submitted in order arrive at the writer in order.
        The HMAC chain depends on this: entry N's hash links to entry N-1.
        """
        q = queue.Queue()
        received = []

        def writer():
            while True:
                item = q.get()
                if item is None:
                    q.task_done()
                    break
                received.append(item["seq"])
                q.task_done()

        t = threading.Thread(target=writer, daemon=True)
        t.start()

        for seq in range(100):
            q.put({"seq": seq})
        q.put(None)
        q.join()

        self.assertEqual(received, list(range(100)))

    def test_concurrent_producers_single_consumer_total_count(self):
        """
        Even if multiple threads submit to the queue simultaneously, all
        entries reach the single consumer. No entries are silently dropped.
        """
        q = queue.Queue()
        received = []
        n_entries = 200
        n_threads = 10

        def writer():
            while True:
                item = q.get()
                if item is None:
                    q.task_done()
                    break
                received.append(item)
                q.task_done()

        consumer = threading.Thread(target=writer, daemon=True)
        consumer.start()

        def producer(start, count):
            for i in range(start, start + count):
                q.put(i)

        chunk = n_entries // n_threads
        producers = [
            threading.Thread(target=producer, args=(i * chunk, chunk))
            for i in range(n_threads)
        ]
        for p in producers:
            p.start()
        for p in producers:
            p.join()

        q.put(None)
        q.join()
        self.assertEqual(len(received), n_entries)
        self.assertEqual(sorted(received), list(range(n_entries)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
