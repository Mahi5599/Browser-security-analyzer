import os
import tempfile

# Keep tests from touching the real SQLite file.
os.environ.setdefault("BSA_DB_PATH", os.path.join(tempfile.gettempdir(), "bsa_test.db"))
