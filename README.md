# Inbox

## Features

- Complete Mail Server: MTA, MDA etc.
- Calendar Sync via CalDav
- Contacts Sync via CardDav
- Transactional Email API via GraphQL

## Architecture

- HTTP Server (GraphQL API + WebDav / CalDav / CardDav etc.)
- SMTP Server (25) - Mail Transfer (Incoming & Outgoing)
- SMTP Server (587) - Mail Submission (Outgoing)
- IMAP Server
