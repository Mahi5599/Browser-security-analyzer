"""Runs the extension's Node unit tests (extension/tests) as part of pytest."""
import os
import shutil
import subprocess

import pytest

EXT = os.path.join(os.path.dirname(__file__), "..", "..", "extension")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_extension_download_scan_unit_tests():
    proc = subprocess.run(["node", "--test", "tests"], cwd=EXT, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-1000:]
