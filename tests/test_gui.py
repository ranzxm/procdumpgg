"""Opt-in Windows GUI startup/close checks; never launches a dump."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import time
import unittest


@unittest.skipUnless(os.name == "nt" and os.environ.get("PD_GUI_TEST_EXE"),
                     "set PD_GUI_TEST_EXE to a built Windows pd_gui.exe")
class GuiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.executable = Path(os.environ["PD_GUI_TEST_EXE"]).resolve(strict=True)

    def test_hidden_render_smoke_with_trailing_whitespace(self):
        result = subprocess.run(f'"{self.executable}" --smoke-test ', shell=False,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))

    def test_minimized_idle_window_closes(self):
        user = ctypes.WinDLL("user32", use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
        user.EnumWindows.restype = wintypes.BOOL
        user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user.GetWindowThreadProcessId.restype = wintypes.DWORD
        user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user.GetClassNameW.restype = ctypes.c_int
        user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user.PostMessageW.restype = wintypes.BOOL
        user.IsWindowVisible.argtypes = [wintypes.HWND]
        user.IsWindowVisible.restype = wintypes.BOOL
        process = subprocess.Popen([str(self.executable)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        windows = []

        @callback_type
        def owned_window(window, _):
            pid = wintypes.DWORD()
            user.GetWindowThreadProcessId(window, ctypes.byref(pid))
            name = ctypes.create_unicode_buffer(256)
            user.GetClassNameW(window, name, len(name))
            if pid.value == process.pid and name.value == "ProcessDumpImGui" and user.IsWindowVisible(window):
                windows.append(window)
            return True

        try:
            deadline = time.monotonic() + 15
            while not windows and process.poll() is None and time.monotonic() < deadline:
                self.assertTrue(user.EnumWindows(owned_window, 0))
                if not windows:
                    time.sleep(0.05)
            self.assertTrue(windows, "No owned GUI window appeared")
            # Queue minimize followed by close against this process's window only.
            self.assertTrue(user.PostMessageW(windows[0], 0x0112, 0xF020, 0))
            self.assertTrue(user.PostMessageW(windows[0], 0x0010, 0, 0))
            _, errors = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, errors.decode("utf-8", "replace"))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


if __name__ == "__main__":
    unittest.main()
