# 20261112-1930-remove-handles-note-chat Remove user handles; note-to-self chat kind

- **status**: completed
- **priority**: P1
- **owner**: gim-core lane of campaign l1-0xhhlawj-20261112-1924
- **createdAt**: 2026-11-12 19:30

## Description

User decisions (2026-11-12):

1. Usernames (handles) are removed; the user id is the only identity.
2. Note to self: a chat of the own devices only, synced across them.

Scope in gim-core: drop handles from the hub API v2 DTOs, routes, vendored
contract, envelope contacts, gim-base and the fake hub; add `ChatKind::Note`
and an MLS group context marker by which joining devices recognise a note
chat. The SQLite store lives in gim-client-sdk (`gim-store-sqlite`).

## Notes

- Recognition: group context extension `NOTE_EXTENSION_TYPE` (`0xF002`),
  see README *Users and chats*.
