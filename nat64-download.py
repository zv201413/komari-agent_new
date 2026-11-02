#!/usr/bin/env python3
"""Download HTTPS through a DNS64 resolver without changing system DNS."""

import argparse
import http.client
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import tempfile
from urllib.parse import urljoin, urlsplit


DEFAULT_DNS64 = "2a00:1098:2c::1"


def skip_name(packet, offset):
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            return offset
        if size & 0xC0 == 0xC0:
            if offset >= len(packet):
                break
            return offset + 1
        if size & 0xC0 or offset + size > len(packet):
            break
        offset += size
    raise ValueError("Malformed DNS name")


def parse_aaaa(packet, query_id):
    if len(packet) < 12:
        raise ValueError("Truncated DNS response")
    response_id, flags, questions, answers, _, _ = struct.unpack("!6H", packet[:12])
    if response_id != query_id or not flags & 0x8000 or flags & 0xF:
        raise ValueError("Invalid or unsuccessful DNS64 response")
    if flags & 0x200:
        raise ValueError("Truncated DNS64 response")
    offset = 12
    for _ in range(questions):
        offset = skip_name(packet, offset) + 4
    result = []
    for _ in range(answers):
        offset = skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS record")
        record_type, record_class, _, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + length > len(packet):
            raise ValueError("Truncated DNS record value")
        if record_type == 28 and record_class == 1 and length == 16:
            address = str(ipaddress.IPv6Address(packet[offset:offset + length]))
            if address not in result:
                result.append(address)
        offset += length
    if not result:
        raise ValueError("DNS64 returned no IPv6 address")
    return result


def resolve_aaaa(host, dns_server, timeout=10):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 6:
            raise ValueError("DNS64 fallback requires a hostname or IPv6 URL")
        return [str(address)]
    labels = host.encode("idna").split(b".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("Invalid DNS hostname")
    query_id = secrets.randbelow(65536)
    query = struct.pack("!6H", query_id, 0x100, 1, 0, 0, 0)
    query += b"".join(bytes([len(label)]) + label for label in labels)
    query += b"\0" + struct.pack("!HH", 28, 1)
    resolver = ipaddress.ip_address(dns_server)
    family = socket.AF_INET6 if resolver.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((str(resolver), 53))
        sock.send(query)
        packet = sock.recv(65535)
    return parse_aaaa(packet, query_id)


class DNS64HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, dns_server, timeout=30):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.dns_server = dns_server

    def connect(self):
        last_error = None
        for address in resolve_aaaa(self.host, self.dns_server):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((address, self.port))
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as error:
                last_error = error
                sock.close()
        raise OSError("Unable to connect through DNS64/NAT64") from last_error


def download(url, output, dns_server=DEFAULT_DNS64):
    for _ in range(8):
        target = urlsplit(url)
        if target.scheme != "https" or not target.hostname or target.username or target.password:
            raise ValueError("Only HTTPS downloads without URL credentials are supported")
        connection = DNS64HTTPSConnection(target.hostname, target.port or 443, dns_server)
        try:
            request_path = target.path or "/"
            if target.query:
                request_path += "?" + target.query
            connection.request("GET", request_path, headers={"User-Agent": "Komari-DNS64-Installer/1"})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Redirect has no destination")
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise ValueError("Download returned HTTP " + str(response.status))
            output = Path(output)
            descriptor, temporary = tempfile.mkstemp(prefix=".dns64-", dir=output.parent)
            try:
                size = 0
                with os.fdopen(descriptor, "wb") as sink:
                    while chunk := response.read(128 * 1024):
                        size += len(chunk)
                        if size > 256 * 1024 * 1024:
                            raise ValueError("Download exceeds 256 MiB")
                        sink.write(chunk)
                if not size:
                    raise ValueError("Empty download")
                os.replace(temporary, output)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return
        finally:
            connection.close()
    raise ValueError("Too many redirects")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dns", default=DEFAULT_DNS64)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        download(args.url, args.output, args.dns)
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, "DNS64/NAT64 download failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
