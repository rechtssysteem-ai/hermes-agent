"""TEMPORARY wine2e diagnostic (never merges): the base scenario of
test_script_killed_before_publishing_the_delegate_runs_no_update, measuring HOW LONG the
never-resumed child takes to die after its script, and whether it was in a job at all."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import time

import pytest

from tests.installation_launcher_fixture import publish_fixture_launcher
from tests.scripts.desktop_update.windows_handoff_support import (
    MARKER, POWERSHELL, HOLD_CLI, ROOT, _script, _HeldLock, _custodian,
)
from tests.scripts.desktop_update.test_desktop_update_windows_marker_lock import FIND_UPDATE_CHILD


def _alive(pid: int) -> bool:
    return str(pid) in subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'],
                                      capture_output=True, text=True, check=False).stdout


@pytest.mark.platforms('windows')
def test_diag(tmp_path: Path) -> None:
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    install = tmp_path / 'checkout'
    publish_fixture_launcher(install, HOLD_CLI)
    home = tmp_path / 'home'; home.mkdir()
    hold = tmp_path / 'release-update'
    marker = home / MARKER
    finder = tmp_path / 'find_child.ps1'
    finder.write_text(FIND_UPDATE_CHILD, encoding='utf-8')
    script = _script(home, install=install, HANDOFF_HOLD=str(hold))
    rec = {}
    lock = None
    try:
        deadline = time.monotonic() + 60
        while not (marker.exists() and _custodian(home, script.pid)
                   and marker.read_bytes().split(b'\n')[0] == _custodian(home, script.pid).encode()):
            assert time.monotonic() < deadline and script.poll() is None
            time.sleep(0.02)
        lock = _HeldLock(home)
        t0 = time.monotonic()
        child = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(finder),
                                '-Parent', str(script.pid), '-Seconds', '60'],
                               capture_output=True, text=True, timeout=90, check=False)
        rec['finder_s'] = round(time.monotonic() - t0, 2)
        pid = int(child.stdout)
        h = k.OpenProcess(0x00100000 | 0x1000, False, pid)
        injob = wintypes.BOOL()
        k.IsProcessInJob(h, None, ctypes.byref(injob))
        rec['in_job'] = bool(injob.value)
        rec['dead_before_kill'] = k.WaitForSingleObject(h, 0) == 0
        subprocess.run(['taskkill', '/F', '/PID', str(script.pid)], capture_output=True, check=True)
        script.wait(timeout=30)
        t1 = time.monotonic()
        rec['dead_at_wait'] = k.WaitForSingleObject(h, 0) == 0
        rec['tasklist_alive_at_wait'] = _alive(pid)
        got = k.WaitForSingleObject(h, 60000)
        rec['death_after_wait_s'] = round(time.monotonic() - t1, 3) if got == 0 else None
        code = wintypes.DWORD()
        k.GetExitCodeProcess(h, ctypes.byref(code))
        rec['exit_code'] = code.value
        rec['tasklist_alive_after'] = _alive(pid)
        rec['ran'] = (Path(str(hold) + '.pid')).exists()
        k.CloseHandle(h)
    finally:
        if lock:
            lock.release()
        hold.touch()
        if script.poll() is None:
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(script.pid)], capture_output=True, check=False)
            script.wait()
        with open(ROOT / '.wine2e-diag.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec) + '\n')
