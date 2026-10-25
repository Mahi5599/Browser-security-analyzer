"""Runs the dashboard's Vitest suite as part of pytest (skipped if deps aren't installed)."""
import os
import shutil
import subprocess

import pytest

DASH = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard")


@pytest.mark.skipif(shutil.which("npm") is None or not os.path.isdir(os.path.join(DASH, "node_modules")),
                    reason="run `npm install` in dashboard/ first")
def test_dashboard_vitest_suite():
    proc = subprocess.run(["npm", "test", "--silent"], cwd=DASH, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-1500:]
