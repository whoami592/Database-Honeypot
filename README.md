# 🍯 Database Honeypot (MySQL Emulation)

A lightweight, **low-interaction MySQL honeypot** written in pure Python. It imitates a MySQL 5.7 server, records every connection attempt, credential guess and SQL statement an intruder sends, and writes everything to a **JSON-lines log** that is easy to feed into a SIEM.

> **Coded by:** Cyber Security Engineer **Mr. Sabaz Ali Khan**

---

## ⚠️ Legal & Safety Notice

This tool is intended for **defensive use only**.

- Deploy it only on systems and networks you **own** or are **explicitly authorised** to monitor.
- Run it on an **isolated host or VLAN**. It never connects to or touches a real database, but any exposed service increases your attack surface.
- Do not run it on a machine that hosts a real MySQL instance on the same port.

The author is not responsible for misuse.

---

## ✨ Features

- Emulates the MySQL handshake (server version `5.7.38-log`, `mysql_native_password`)
- Two operating modes: **deny** and **lure**
- Logs source IP/port, username, requested database and the authentication response
- **Weak-password detection**: checks each login against a list of commonly guessed passwords
- Records every SQL statement typed by an attacker in lure mode
- Detects scanner probes (connections that send no valid handshake response)
- Thread-per-connection with a configurable connection limit and idle timeout
- Colour-coded console output plus a session summary on exit
- **No third-party dependencies** (Python standard library only)

---

## 🔀 Modes

| Mode | Behaviour | Best for |
|------|-----------|----------|
| `deny` *(default)* | Every login is rejected with `Access denied`. | Collecting credential guesses and brute-force sources. |
| `lure` | Accepts any login, answers a few queries with fake data and logs every statement. | Observing what an attacker does after getting in. |

### Fake responses in `lure` mode

| Query | Response |
|-------|----------|
| `SELECT VERSION()` / `SELECT @@version` | `5.7.38-log` |
| `SELECT DATABASE()` | `NULL` |
| `SELECT USER()` / `SELECT CURRENT_USER()` | `root@localhost` |
| `SHOW DATABASES` | `information_schema` |
| `DROP`, `DELETE`, `TRUNCATE`, `INSERT`, `UPDATE`, `CREATE`, `ALTER`, `GRANT` | Error 1142 (command denied) |
| Anything else | Generic `OK` packet |

All statements are logged regardless of the reply.

---

## 📦 Requirements

- Python **3.6+**
- No external packages

---

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
chmod +x db_honeypot.py
```

---

## 🛠️ Usage

```bash
# Default: listen on 0.0.0.0:3306 in deny mode
python3 db_honeypot.py

# Lure mode on a custom port
python3 db_honeypot.py --mode lure -p 3307

# Custom log file location
python3 db_honeypot.py --log /var/log/dbhoneypot.jsonl

# Bind to a specific interface with a shorter idle timeout
python3 db_honeypot.py --host 192.168.1.50 --timeout 15
```

Press **Ctrl+C** to stop. A session summary is printed on exit.

### Command-line options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `0.0.0.0` | Address to bind to |
| `-p`, `--port` | `3306` | Port to listen on |
| `--mode` | `deny` | `deny` (reject all logins) or `lure` (accept and log queries) |
| `--log` | `honeypot_events.jsonl` | JSON-lines log file |
| `--timeout` | `30` | Per-connection idle timeout in seconds |
| `--max-conns` | `100` | Maximum simultaneous connections |

---

## 📝 Log Format

Each event is written as one JSON object per line.

| Event | Description |
|-------|-------------|
| `connect` | New TCP connection (`src`, `sport`) |
| `probe` | Connection with no valid handshake response, likely a port scanner |
| `login_attempt` | Credential attempt (`user`, `db`, `used_password`, `salt`, `auth_response`, `weak_password`) |
| `query` | SQL statement sent in lure mode (`user`, `sql`, truncated to 2000 characters) |
| `disconnect` | Connection closed |

### Example

```json
{"time": "2026-11-09T10:15:42.120345+00:00", "event": "connect", "src": "203.0.113.45", "sport": 51822}
{"time": "2026-11-09T10:15:42.131002+00:00", "event": "login_attempt", "src": "203.0.113.45", "user": "root", "db": "", "used_password": true, "salt": "...", "auth_response": "...", "weak_password": "123456"}
{"time": "2026-11-09T10:15:43.402118+00:00", "event": "query", "src": "203.0.113.45", "user": "root", "sql": "SELECT VERSION()"}
{"time": "2026-11-09T10:15:44.010774+00:00", "event": "disconnect", "src": "203.0.113.45"}
```

### Quick analysis with `jq`

```bash
# Top attacking IPs
jq -r 'select(.event=="login_attempt") | .src' honeypot_events.jsonl | sort | uniq -c | sort -rn | head

# Usernames being tried
jq -r 'select(.event=="login_attempt") | .user' honeypot_events.jsonl | sort | uniq -c | sort -rn

# All captured SQL statements
jq -r 'select(.event=="query") | "\(.src)  \(.sql)"' honeypot_events.jsonl
```

---

## 🧠 How It Works

1. The server sends a MySQL v10 handshake packet containing a random salt.
2. The client replies with its username, optional database and a scrambled password response.
3. The honeypot parses the response and compares it against a small list of common passwords to flag **weak-password hits** (the plaintext password is never stored, only the match result).
4. In `deny` mode it returns error `1045 Access denied`. In `lure` mode it returns `OK` and then handles `COM_QUERY`, `COM_PING`, `COM_INIT_DB` and `COM_QUIT` commands.

> **Note:** The log contains the salt and the raw authentication response. Treat the log file as sensitive, since these values could be used for offline password cracking.

---

## 🔒 Deployment Tips

- Run as an **unprivileged user** and, ideally, inside a container or VM.
- Use a firewall to restrict where the honeypot can send traffic (it should never need outbound access).
- Ship the JSONL log to your SIEM (Splunk, ELK, Wazuh, etc.) and alert on `login_attempt` events with a non-null `weak_password`, and on any `query` event.
- Rotate the log file regularly (for example with `logrotate`).
- Make sure no real database service uses the same port on the same host.

---

## ⚙️ Limitations

- Low-interaction only: it does not implement a real SQL engine.
- SSL/TLS is not offered, so clients that require TLS will fail to connect.
- Only `mysql_native_password` is emulated.
- Advanced fingerprinting tools may be able to tell it apart from a real MySQL server.

---

## 🗺️ Possible Improvements

- Add GeoIP enrichment for source addresses
- Send alerts to Telegram, Slack or email
- Support more fake tables and query responses
- Add TLS support

---

## 👤 Author

**Cyber Security Engineer Mr. Sabaz Ali Khan**

Coded by Mr. Sabaz Ali Khan.

---

## 📄 License

Released under the [MIT License](LICENSE). Add a `LICENSE` file to your repository if you want to use this license.
