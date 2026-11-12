# 20261112-1930-remove-handles-note-chat Remove user handles; note to self

- **status**: completed
- **priority**: P1
- **owner**: gim-core lane of campaign l1-0xhhlawj-20261112-1924
- **createdAt**: 2026-11-12 19:30

## Description

User decisions (2026-11-12):

1. Usernames (handles) are removed; the user id is the only identity.
2. Note to self is the direct chat with yourself (no separate chat kind).

Scope in gim-core: drop handles from the hub API v2 DTOs, routes, vendored
contract, envelope contacts, gim-base and the fake hub; make a direct chat
whose peer is the own user work in gim-base (peer, lookup, add check). The
SQLite store lives in gim-client-sdk (`gim-store-sqlite`).

## Notes

- A first version added `ChatKind::Note` with an MLS group context marker;
  reverted after the user chose the direct chat with yourself.
