# mailproxy

An IMAP/SMTP proxy that handles OAuth2 authentication and keeps a local copy
of all messages. Clients connect with plain IMAP/SMTP and a password — the
proxy transparently refreshes OAuth2 tokens, forwards to the remote server,
and syncs to a local SQLite database.

## Problem

Gmail, Outlook, and Yahoo require OAuth2 (XOAUTH2) for IMAP/SMTP access.
App passwords are deprecated or disabled. This means any application that
reads or sends email must implement the OAuth2 flow: obtain a refresh token,
manage token expiry, and perform XOAUTH2 SASL auth for both IMAP and SMTP.
This setup is duplicated per application and requires persistent token state.

mailproxy centralizes this: it runs a local IMAP and SMTP server that accepts
plain password auth, handles OAuth2 token refresh internally, and forwards all
commands to the remote provider. Applications connect to the proxy with a
simple password and get standard IMAP/SMTP — OAuth2 is handled once, in one
place.

As a side effect, all synced messages are stored locally in SQLite with
soft-delete semantics, providing a backup independent of the provider.

## Quick start

```
pip install -e .
```

Create `config.json`:

```json
{
  "domain": "example.com",
  "log_level": "DEBUG",
  "host": "127.0.0.1",
  "imap_port": 9143,
  "smtp_port": 9587,
  "db_path": "temp/maildata.sqlite"
}
```

Get an OAuth2 refresh token (for Gmail/Outlook/Yahoo):

```
mailproxy login --preset gmail
```

Add your account:

```
mailproxy account add -C config.json -A you@gmail.com --preset gmail --refresh-token "1//0g..."
```

Run the proxy:

```
export MAILPROXY_PASSWORD=yourproxypassword
mailproxy run -C config.json
```

Point your mail client or scripts at the configured `host`:`imap_port` (IMAP)
and `host`:`smtp_port` (SMTP). Use any username and the proxy password you set.

## Features

- Handles OAuth2 token refresh internally; clients authenticate with a password
- Local SQLite cache with soft-delete — deleted messages are marked, not removed
- Standard IMAP4rev1 and SMTP — any IMAP/SMTP library works as a client
- Virtual mailboxes (`Virtual/All`, `Virtual/Unseen`, `Virtual/Flagged`) for
  cross-folder views
- IDLE for push notifications from the remote server
- STARTTLS and implicit TLS on both IMAP and SMTP
- Presets for Gmail, Microsoft, and Yahoo; custom OAuth2 configs supported
- Zero runtime dependencies (Python 3.13 standard library)

## Configuration

| Field         | Type   | Default     | Description                              |
|---------------|--------|-------------|------------------------------------------|
| `domain`      | string | required    | Domain shown in the IMAP greeting        |
| `log_level`   | string | `"DEBUG"`   | Python logging level                     |
| `host`        | string | `"0.0.0.0"` | Bind address                            |
| `imap_port`   | int    | `143`       | Local IMAP port                         |
| `smtp_port`   | int    | `587`       | Local SMTP port                         |
| `db_path`     | string | required    | Path to the SQLite database              |

The proxy password is read from the `MAILPROXY_PASSWORD` environment variable.

## Commands

```
mailproxy login -C config.json --preset gmail          # OAuth2 login flow
mailproxy account add -C config.json -A you@... ...     # Add an account
mailproxy account list -C config.json                   # List accounts
mailproxy account remove -C config.json -A you@...      # Remove an account
mailproxy get-access-token -C config.json -A you@...    # Test OAuth2 refresh
mailproxy run -C config.json                            # Run the proxy
mailproxy dev -C config.json -A you@...                 # Debug a remote connection
```

### Adding accounts

**OAuth2 (Gmail, Outlook, Yahoo, or custom):**

```
mailproxy account add -C config.json -A you@gmail.com --preset gmail --refresh-token "1//0g..."
```

**Plain password (any IMAP/SMTP provider):**

```
mailproxy account add -C config.json -A you@example.com \
  --imap-host imap.example.com --imap-port 993 --imap-tlsmode DIRECT \
  --smtp-host smtp.example.com --smtp-port 587 --smtp-tlsmode STARTTLS \
  --password yourpassword
```

Multiple addresses can be added by repeating `-A`; the first is the account key.

## Backup behavior

When a message or mailbox is deleted (via `EXPUNGE`, `CLOSE`, or `DELETE`),
the operation is forwarded to the remote server as normal, but locally the
record is **soft-deleted** rather than removed from disk:

- Soft-deleted items are hidden from all queries — the proxy behaves
  identically to a normal server from the client's perspective
- If the remote still has the message, re-syncing automatically restores it
- If the remote has lost the data, the soft-deleted record persists as a
  permanent local backup

`account remove` is the only operation that hard-deletes data.

## Usage examples

Standard IMAP/SMTP libraries work as clients:

```python
import imaplib, email

imap = imaplib.IMAP4("host", 9143)
imap.login("anything", "yourproxypassword")
imap.select("INBOX")

_, msgs = imap.search(None, 'SUBJECT', '"invoice"')
for num in msgs[0].split():
  _, data = imap.fetch(num, "(RFC822)")
  msg = email.message_from_bytes(data[0][1])
  # process message, move, flag, etc.
  imap.store(num, "+FLAGS", "\\Seen")
  imap.copy(num, "Invoices")
```

```python
import smtplib

smtp = smtplib.SMTP("host", 9587)
smtp.login("anything", "yourproxypassword")
smtp.sendmail("you@example.com", "client@example.com", "Your invoice is ready")
```

## Testing

```
python -m unittest discover -s tests    # 112 unit tests
python -m tests.e2e_test               # end-to-end protocol test
python -m ruff check mailproxy/ tests/ # lint
```

## Architecture

```
mailproxy/
  bin.py            CLI entry point
  config.py         Config validation
  model.py          Data models (Account, Config, Mailbox, Message)
  db.py             SQLite layer (schema, migrations, soft-delete)
  imap_frontend.py  IMAP server (serves clients)
  imap_backend.py   IMAP client (connects to remote, syncs)
  smtp_frontend.py  SMTP server (serves clients)
  smtp_backend.py   SMTP client (forwards mail to remote)
  auth.py           Proxy auth + OAuth2 token refresh
  imap_parsing.py   IMAP protocol parsing
  utils.py          Stream reader, helpers
  presets/          Provider configs (gmail, microsoft, yahoo)
  assets/           TLS certificates for STARTTLS
```

The proxy maintains a SQLite database with `accounts`, `mailboxes`, and
`messages` tables. On `SELECT` or `NOOP`, the backend syncs new messages and
flag changes from the remote. Virtual mailboxes are computed on-the-fly.

## TLS modes

| Mode       | Behavior                          |
|------------|-----------------------------------|
| `DIRECT`   | Implicit TLS (port 993/465)      |
| `STARTTLS` | Upgrade after initial handshake   |
| `NONE`     | Plaintext                         |

## RFCs

- [IMAP4rev1](https://www.rfc-editor.org/rfc/rfc3501.html)
- [IMAP4rev2](https://www.rfc-editor.org/rfc/rfc9051.html)
- [SMTP](https://www.rfc-editor.org/rfc/rfc5321.html)
- [SMTP AUTH](https://www.rfc-editor.org/rfc/rfc4954.html)
- [OAUTH2](https://www.rfc-editor.org/rfc/rfc6749.html)
