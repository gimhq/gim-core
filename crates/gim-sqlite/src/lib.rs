//! rusqlite (bundled) implementation of `StateStore` + `CryptoStore` on one
//! database, migrations, and a shared transaction so MLS state and message
//! rows commit atomically.

#![forbid(unsafe_code)]
