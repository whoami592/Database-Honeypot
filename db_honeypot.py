#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database Honeypot (MySQL emulation)
Coded by: Cyber Security Engineer Mr. Sabaz Ali Khan

A low-interaction MySQL honeypot for defensive use. It imitates a MySQL 5.7
server, records every connection attempt (source IP, username, database,
password hash challenge/response, weak-password hits) and every query an
intruder runs, and writes everything to a JSON-lines log for your SIEM.

Modes
  deny  (default)  every login gets "Access denied" -> logs credential guesses
  lure             accepts any login, answers a few queries with fake data
                   and logs every statement the attacker types

Only deploy on systems/networks you own or are authorised to monitor.
Run it on an isolated host/VLAN; it never touches a real database.

Usage
  python3 db_honeypot.py                       # port 3306, deny mode
  python3 db_honeypot.py --mode lure -p 3307
  python3 db_honeypot.py --log /var/log/dbhoneypot.jsonl
"""

import argparse
import datetime
import hashlib
import json
import os
import signal
import socket
import struct
import sys
import threading
from collections import Counter

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀
⠀⠀⢠⣿⡿⠿⠿⠿⠿⠿⠿⠿⣿⠿⠿⠿⠿⠿⠿⢿⣿⣿⣿⠿⠿⢿⣿⡄⠀⠀
⠀⢀⣿⣿⡇⠀⠀⣠⣤⣄⣀⣠⣿⠀⠀⢀⣤⣀⡀⠀⠘⣿⣿⠀⠀⢸⣿⣿⡀⠀
⠀⢸⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⠟⠀⠀⣿⣿⠀⠀⢸⣿⣿⡇⠀
⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠺⣿⣿⠀⠀⢸⣿⣿⡧⠀
⠀⢸⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⢸⣿⣿⣿⠀⠀⢹⣿⠀⠀⢸⣿⣿⡇⠀
⠀⠈⣿⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⠈⠛⠛⠉⠀⢀⣾⣿⠀⠀⢸⣿⣿⠃⠀
⠀⠀⠸⣿⣷⣶⣶⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣾⣿⣿⣿⣶⣶⣾⣿⠇⠀⠀
⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = "Database Honeypot  |  Coded by Cyber Security Engineer Mr. Sabaz Ali Khan"

SERVER_VERSION = "5.7.38-log"

# Capability flags
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH_LENENC = 0x00200000

# Small list of passwords attackers love to try; used to flag weak-password hits.
COMMON_PASSWORDS = [
    "", "root", "admin", "password", "123456", "12345678", "123456789",
    "toor", "mysql", "test", "qwerty", "letmein", "changeme", "P@ssw0rd",
    "admin123", "root123", "password1", "1234", "12345", "welcome", "pass",
]

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

log_lock = threading.Lock()
stats = Counter()
unique_ips = set()


# --------------------------------------------------------------------------
# MySQL wire-protocol helpers
# --------------------------------------------------------------------------
def lenenc_int(n: int) -> bytes:
    if n < 251:
        return bytes([n])
    if n < 65536:
        return b"\xfc" + struct.pack("<H", n)
    return b"\xfd" + struct.pack("<I", n)[:3]


def lenenc_str(s: str) -> bytes:
    b = s.encode()
    return lenenc_int(len(b)) + b


def packet(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def ok_packet(seq: int) -> bytes:
    return packet(seq, b"\x00\x00\x00" + struct.pack("<HH", 0x0002, 0))


def err_packet(seq: int, code: int, state: str, msg: str) -> bytes:
    return packet(seq, b"\xff" + struct.pack("<H", code) + b"#" + state.encode() + msg.encode())


def eof_packet(seq: int) -> bytes:
    return packet(seq, b"\xfe" + struct.pack("<HH", 0, 0x0002))


def single_value_result(seq: int, col: str, value: str) -> bytes:
    """Text-protocol result set: one column, one row."""
    out = packet(seq, lenenc_int(1))
    seq += 1
    coldef = (
        lenenc_str("def") + lenenc_str("") + lenenc_str("") + lenenc_str("")
        + lenenc_str(col) + lenenc_str(col)
        + b"\x0c" + struct.pack("<H", 0x21) + struct.pack("<I", 255)
        + b"\xfd" + struct.pack("<H", 0) + b"\x00" + b"\x00\x00"
    )
    out += packet(seq, coldef)
    seq += 1
    out += eof_packet(seq)
    seq += 1
    out += packet(seq, lenenc_str(value))
    seq += 1
    out += eof_packet(seq)
    return out


def build_handshake(thread_id: int, salt: bytes) -> bytes:
    caps_lower = 0xF7FF   # no SSL bit -> client sends plain handshake response
    caps_upper = 0x0008   # CLIENT_PLUGIN_AUTH
    payload = (
        b"\x0a" + SERVER_VERSION.encode() + b"\x00"
        + struct.pack("<I", thread_id)
        + salt[:8] + b"\x00"
        + struct.pack("<H", caps_lower)
        + b"\x21"                       # utf8_general_ci
        + struct.pack("<H", 0x0002)     # status: autocommit
        + struct.pack("<H", caps_upper)
        + b"\x15"                       # auth data length (21)
        + b"\x00" * 10
        + salt[8:20] + b"\x00"
        + b"mysql_native_password\x00"
    )
    return packet(0, payload)


def read_packet(sock: socket.socket):
    header = recv_exact(sock, 4)
    if not header:
        return None, None
    length = int.from_bytes(header[:3], "little")
    seq = header[3]
    if length > 1_000_000:           # sanity cap
        return None, None
    return seq, recv_exact(sock, length)


def recv_exact(sock: socket.socket, n: int):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def parse_handshake_response(payload: bytes) -> dict:
    caps = struct.unpack("<I", payload[0:4])[0]
    pos = 32                                     # caps+maxpkt+charset+filler
    end = payload.index(b"\x00", pos)
    user = payload[pos:end].decode("utf-8", "replace")
    pos = end + 1
    auth = b""
    if caps & CLIENT_PLUGIN_AUTH_LENENC:
        ln = payload[pos]
        pos += 1
        auth = payload[pos:pos + ln]
        pos += ln
    elif caps & CLIENT_SECURE_CONNECTION:
        ln = payload[pos]
        pos += 1
        auth = payload[pos:pos + ln]
        pos += ln
    else:
        end = payload.index(b"\x00", pos)
        auth = payload[pos:end]
        pos = end + 1
    db = ""
    if caps & CLIENT_CONNECT_WITH_DB and pos < len(payload):
        end = payload.find(b"\x00", pos)
        end = len(payload) if end == -1 else end
        db = payload[pos:end].decode("utf-8", "replace")
    return {"user": user, "auth": auth, "db": db}


def native_password_response(password: str, salt: bytes) -> bytes:
    """mysql_native_password scramble, used to spot weak passwords."""
    if password == "":
        return b""
    s1 = hashlib.sha1(password.encode()).digest()
    s2 = hashlib.sha1(s1).digest()
    s3 = hashlib.sha1(salt + s2).digest()
    return bytes(a ^ b for a, b in zip(s1, s3))


def check_weak_password(auth: bytes, salt: bytes):
    for pw in COMMON_PASSWORDS:
        if native_password_response(pw, salt) == auth:
            return pw
    return None


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
def log_event(logfile: str, event: str, **fields):
    record = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False)
    with log_lock:
        with open(logfile, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    colour = {"connect": CYAN, "login_attempt": YELLOW, "query": RED,
              "disconnect": GREEN}.get(event, RESET)
    summary = " ".join(f"{k}={v!r}" for k, v in fields.items())
    print(f"{colour}[{record['time'][11:19]}] {event:<13}{RESET} {summary}")


# --------------------------------------------------------------------------
# Connection handler
# --------------------------------------------------------------------------
def fake_query_reply(query: str, seq: int) -> bytes:
    q = query.strip().rstrip(";").lower()
    if q in ("select version()", "select @@version"):
        return single_value_result(seq, "version()", SERVER_VERSION)
    if q in ("select database()",):
        return single_value_result(seq, "database()", "NULL")
    if q in ("select user()", "select current_user()"):
        return single_value_result(seq, "user()", "root@localhost")
    if q.startswith("show databases"):
        return single_value_result(seq, "Database", "information_schema")
    if q.startswith(("drop", "delete", "truncate", "insert", "update", "create", "alter", "grant")):
        return err_packet(seq, 1142, "42000", "command denied to user for table")
    return ok_packet(seq)


def handle_client(conn: socket.socket, addr, args, thread_id: int):
    ip, port = addr
    stats["connections"] += 1
    unique_ips.add(ip)
    log_event(args.log, "connect", src=ip, sport=port)
    conn.settimeout(args.timeout)
    salt = os.urandom(20)
    # keep salt bytes away from NUL so the scramble round-trips cleanly
    salt = bytes((b % 94) + 33 for b in salt)
    try:
        conn.sendall(build_handshake(thread_id, salt))
        seq, payload = read_packet(conn)
        if payload is None or len(payload) < 33:
            log_event(args.log, "probe", src=ip, note="no/short handshake response (scanner?)")
            stats["probes"] += 1
            return
        info = parse_handshake_response(payload)
        weak = check_weak_password(info["auth"], salt)
        stats["login_attempts"] += 1
        log_event(
            args.log, "login_attempt", src=ip, user=info["user"], db=info["db"],
            used_password=bool(info["auth"]),
            salt=salt.decode(), auth_response=info["auth"].hex(),
            weak_password=weak,
        )

        if args.mode == "deny":
            msg = f"Access denied for user '{info['user']}'@'{ip}' (using password: {'YES' if info['auth'] else 'NO'})"
            conn.sendall(err_packet(seq + 1, 1045, "28000", msg))
            return

        # lure mode: let them in and record everything they type
        conn.sendall(ok_packet(seq + 1))
        while True:
            seq, payload = read_packet(conn)
            if payload is None or not payload:
                break
            cmd = payload[0]
            if cmd == 0x01:                       # COM_QUIT
                break
            if cmd == 0x0E:                       # COM_PING
                conn.sendall(ok_packet(seq + 1))
            elif cmd == 0x02:                     # COM_INIT_DB (USE db)
                conn.sendall(ok_packet(seq + 1))
            elif cmd == 0x03:                     # COM_QUERY
                query = payload[1:].decode("utf-8", "replace")
                stats["queries"] += 1
                log_event(args.log, "query", src=ip, user=info["user"], sql=query[:2000])
                conn.sendall(fake_query_reply(query, seq + 1))
            else:
                conn.sendall(err_packet(seq + 1, 1047, "08S01", "Unknown command"))
    except (socket.timeout, ConnectionError, OSError, ValueError, IndexError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log_event(args.log, "disconnect", src=ip)


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
def print_summary():
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{GREEN}Session summary{RESET}")
    print(f"  connections    : {stats['connections']}")
    print(f"  unique sources : {len(unique_ips)}")
    print(f"  login attempts : {stats['login_attempts']}")
    print(f"  queries logged : {stats['queries']}")
    print(f"  scanner probes : {stats['probes']}")
    print(f"{CYAN}{'=' * 60}{RESET}")


def main():
    ap = argparse.ArgumentParser(description="MySQL database honeypot by Mr. Sabaz Ali Khan")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("-p", "--port", type=int, default=3306, help="listen port (default 3306)")
    ap.add_argument("--mode", choices=["deny", "lure"], default="deny",
                    help="deny = reject all logins; lure = accept and log queries")
    ap.add_argument("--log", default="honeypot_events.jsonl", help="JSON-lines log file")
    ap.add_argument("--timeout", type=int, default=30, help="per-connection idle timeout (s)")
    ap.add_argument("--max-conns", type=int, default=100, help="max simultaneous connections")
    args = ap.parse_args()

    print(CYAN + BANNER + RESET)
    print(f"{GREEN}{CREDIT}{RESET}\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        sys.exit(f"{RED}Cannot bind to port {args.port} (need root for ports < 1024?){RESET}")
    except OSError as e:
        sys.exit(f"{RED}Cannot bind to {args.host}:{args.port} - {e}{RESET}")
    srv.listen(64)
    srv.settimeout(1.0)

    print(f"[*] Listening on {args.host}:{args.port}  mode={args.mode}  log={args.log}")
    print("[*] Press Ctrl+C to stop\n")

    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    slots = threading.BoundedSemaphore(args.max_conns)
    thread_id = 1000
    while running:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if not slots.acquire(blocking=False):
            conn.close()
            continue
        thread_id += 1

        def worker(c=conn, a=addr, t=thread_id):
            try:
                handle_client(c, a, args, t)
            finally:
                slots.release()

        threading.Thread(target=worker, daemon=True).start()

    srv.close()
    print_summary()


if __name__ == "__main__":
    main()
