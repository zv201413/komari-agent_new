import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallActions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.target = self.root / "komari"
        self.target.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.marker = self.root / "downloaded"
        for name in ["curl", "wget"]:
            command = self.tools / name
            command.write_text('#!/bin/sh\nprintf download >> "$KOMARI_ACTION_MARKER"\nexit 7\n')
            command.chmod(0o700)
        self.config = self.root / "config"
        self.config.mkdir()
        self.env = dict(os.environ, PATH=str(self.tools) + ":" + os.environ["PATH"], KOMARI_ACTION_MARKER=str(self.marker), XDG_CONFIG_HOME=str(self.config))
        self.name = "komari-action-fixture"
        self.pid_file = self.target / (self.name + ".pid")
        if os.geteuid() == 0:
            self.pid_file = Path("/var/run") / (self.name + ".pid")
            self.addCleanup(lambda: self.pid_file.unlink(missing_ok=True))

    def run_installer(self, *args):
        return subprocess.run(["bash", str(ROOT / "install.sh"), "--install-dir", str(self.target), "--install-service-name", self.name, "--background", *args], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def start_agent_fixture(self):
        binary = self.target / "agent"
        shutil.copyfile("/bin/sleep", binary)
        binary.chmod(0o700)
        process = subprocess.Popen([str(binary), "30"])
        self.addCleanup(lambda: (process.terminate() if process.poll() is None else None, process.wait()))
        self.pid_file.write_text(str(process.pid))
        return process

    def test_status_never_downloads_and_is_read_only(self):
        self.start_agent_fixture()
        before = self.pid_file.read_bytes()
        result = self.run_installer("-e", "https://example.test", "-t", "fixture", "status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"is running", result.stdout)
        self.assertEqual(self.pid_file.read_bytes(), before)
        self.assertFalse(self.marker.exists())
        self.assertNotIn(b"Binary arguments", result.stdout)

    def test_status_without_an_install_does_not_create_files(self):
        result = self.run_installer("status")
        self.assertEqual(result.returncode, 3)
        self.assertIn(b"not installed", result.stdout)
        self.assertEqual(list(self.target.iterdir()), [])
        self.assertFalse(self.marker.exists())

    def test_del_stops_background_process_and_preserves_unrelated_data(self):
        process = self.start_agent_fixture()
        for name in ["agent.sh", self.name + ".sh", "agent.log", "custom.txt"]:
            (self.target / name).write_text("fixture")
        result = self.run_installer("del")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        process.wait(timeout=5)
        self.assertEqual(process.returncode, -signal.SIGTERM)
        self.assertEqual([p.name for p in self.target.iterdir()], ["custom.txt"])
        self.assertFalse(self.marker.exists())
        again = self.run_installer("del")
        self.assertEqual(again.returncode, 0)

    def test_stale_pid_does_not_kill_an_unrelated_process(self):
        process = subprocess.Popen(["/bin/sleep", "30"])
        self.addCleanup(lambda: (process.terminate() if process.poll() is None else None, process.wait()))
        (self.target / "agent").write_text("old")
        self.pid_file.write_text(str(process.pid))
        result = self.run_installer("del")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(process.poll())

    def test_del_stops_an_overwritten_agent_without_a_pid_file(self):
        process = self.start_agent_fixture()
        self.pid_file.unlink()
        (self.target / "agent").unlink()
        result = self.run_installer("del")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        process.wait(timeout=5)
        self.assertEqual(process.returncode, -signal.SIGTERM)

    def test_rep_failed_download_keeps_the_previous_process_and_binary(self):
        process = self.start_agent_fixture()
        before = (self.target / "agent").read_bytes()
        result = self.run_installer("--install-dns64", "off", "rep")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Replacement requested", result.stdout)
        self.assertEqual((self.target / "agent").read_bytes(), before)
        self.assertIsNone(process.poll())

    def test_rep_success_replaces_the_process_and_consumes_the_suffix(self):
        previous = self.start_agent_fixture()
        curl = self.tools / "curl"
        curl.write_text('''#!/bin/sh
printf download >> "$KOMARI_ACTION_MARKER"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then cp /bin/sleep "$2"; exit 0; fi
  shift
done
exit 7
''')
        result = self.run_installer("--install-dns64", "off", "30", "rep")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        previous.wait(timeout=5)
        new_pid = int(self.pid_file.read_text())
        self.assertNotEqual(new_pid, previous.pid)
        launcher = (self.target / (self.name + ".sh")).read_text()
        self.assertIn('ARGS="30"', launcher)
        self.assertNotIn('ARGS="30 rep"', launcher)
        # Exercise actual uninstall for the newly installed process as cleanup.
        self.addCleanup(lambda: self.run_installer("del"))
        for _ in range(20):
            if Path(f"/proc/{new_pid}/exe").exists():
                break
            time.sleep(0.01)
        self.assertEqual(self.run_installer("status").returncode, 0)

    def test_default_dns64_is_fallback_and_explicit_dns_is_preserved(self):
        result = self.run_installer("-e", "https://example.test", "-t", "fixture", "rep")
        self.assertIn(b"--fallback-dns 2a00:1098:2c::1", result.stdout)
        self.assertNotIn(b"--custom-dns 2a00:1098:2c::1", result.stdout)
        result = self.run_installer("--custom-dns", "1.1.1.1", "--install-dns64", "off", "rep")
        self.assertIn(b"--custom-dns 1.1.1.1", result.stdout)
        self.assertNotIn(b"--fallback-dns", result.stdout)

    @unittest.skipIf(os.geteuid() == 0, "fixture targets a non-root systemd user installation")
    def test_status_uses_the_existing_user_service_without_installing(self):
        unit = self.config / "systemd/user" / (self.name + ".service")
        unit.parent.mkdir(parents=True)
        unit.write_text("fixture")
        systemctl = self.tools / "systemctl"
        systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\nexit 0\n')
        systemctl.chmod(0o700)
        result = self.run_installer("status")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"--user status --no-pager", result.stdout)
        self.assertEqual(unit.read_text(), "fixture")
        self.assertFalse(self.marker.exists())

    @unittest.skipIf(os.geteuid() == 0, "fixture targets a non-root systemd user installation")
    def test_del_removes_inactive_user_unit_without_a_user_bus(self):
        unit = self.config / "systemd/user" / (self.name + ".service")
        unit.parent.mkdir(parents=True)
        unit.write_text("fixture")
        systemctl = self.tools / "systemctl"
        systemctl.write_text('#!/bin/sh\nexit 1\n')
        systemctl.chmod(0o700)
        result = self.run_installer("del")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(unit.exists())
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
