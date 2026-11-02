import importlib.util
import ipaddress
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nat64_download", ROOT / "nat64-download.py")
nat64 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nat64)


class Response:
    def __init__(self, status=200, chunks=None, location=None):
        self.status = status
        self.chunks = iter(chunks if chunks is not None else [b"agent", b""])
        self.location = location

    def getheader(self, name):
        return self.location

    def read(self, _):
        result = next(self.chunks)
        if isinstance(result, Exception):
            raise result
        return result


class Connection:
    response = None

    def __init__(self, *args):
        pass

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return self.response

    def close(self):
        pass


class DNS64Tests(unittest.TestCase):
    def test_compressed_dns64_answer_and_invalid_responses(self):
        address = ipaddress.IPv6Address("2a00:1098:2b::808:808")
        packet = struct.pack("!6H", 123, 0x8180, 1, 1, 0, 0)
        packet += b"\x06github\x03com\0" + struct.pack("!HH", 28, 1)
        packet += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + address.packed
        self.assertEqual(nat64.parse_aaaa(packet, 123), [str(address)])
        for broken in [packet[:8], packet[:-1], packet]:
            with self.assertRaises(ValueError):
                nat64.parse_aaaa(broken, 321 if broken == packet else 123)

    def test_tls_still_verifies_certificate_and_original_hostname(self):
        connection = nat64.DNS64HTTPSConnection("github.com", 443, nat64.DEFAULT_DNS64)
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)
        with patch.object(nat64, "resolve_aaaa", return_value=["2001:db8::1"]), patch.object(nat64.socket, "socket") as sockets, patch.object(connection._context, "wrap_socket", side_effect=ssl.SSLCertVerificationError("bad certificate")) as wrap:
            with self.assertRaises(OSError):
                connection.connect()
            wrap.assert_called_once_with(sockets.return_value, server_hostname="github.com")

    def test_download_is_atomic_and_rejects_empty_http_errors_and_plaintext_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "agent"
            output.write_bytes(b"previous")
            for response in [Response(chunks=[b"partial", OSError("lost connection")]), Response(chunks=[b""]), Response(status=404), Response(status=302, location="http://github.com/plaintext")]:
                Connection.response = response
                with patch.object(nat64, "DNS64HTTPSConnection", Connection), self.assertRaises((ValueError, OSError)):
                    nat64.download("https://github.com/agent", output)
                self.assertEqual(output.read_bytes(), b"previous")
                self.assertEqual(list(Path(directory).iterdir()), [output])
            Connection.response = Response()
            with patch.object(nat64, "DNS64HTTPSConnection", Connection):
                nat64.download("https://github.com/agent", output)
            self.assertEqual(output.read_bytes(), b"agent")

    def test_failed_installer_download_preserves_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            for name in ["curl", "wget"]:
                command = tools / name
                command.write_text("#!/bin/sh\nexit 7\n")
                command.chmod(0o700)
            target = root / "komari"
            target.mkdir()
            binary = target / "agent"
            binary.write_bytes(b"previous-agent")
            import os
            env = dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"])
            result = subprocess.run(["bash", str(ROOT / "install.sh"), "--install-dir", str(target), "--install-service-name", "dns64-test-fixture", "--install-dns64", "off", "-e", "https://example.test", "-t", "fixture"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(binary.read_bytes(), b"previous-agent")
            self.assertIn(b"previous installation has been preserved", result.stdout)


if __name__ == "__main__":
    unittest.main()
