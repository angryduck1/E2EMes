# EE2E Messenger writed on C++.

<BinBin>
Copyright (C) 2026 <BinBin>

![Project Status](https://img.shields.io/badge/in_development-now)

![C++](https://img.shields.io/badge/C++-20-blue?logo=cplusplus&logoColor=white)
![Boost.Asio](https://img.shields.io/badge/Boost.Asio-1.74+-green)
![Redis](https://shields.io/badge/Redis-red)
![SQLite](https://shields.io/badge-SQLite-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

## Overview
E2EMes is a messenger with continious end-to-end encryption.

- End-To-End encryption is a main act of security
- Fast working and easy for use
- Comfortbale session system of authorization.
- General cryption system.
- Redis db for fast control of sessions.
- SQLite for storage a messages and other content.

## Location

See the *client* folder [CLIENT](./client)
See the *server* folder [SERVER](./server)

## Install

You need to install *libsodium* *boost-asio* *redis*. Build *cmake* file.
After install run *server*, *redis-server* and enjoy of process!

### License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
See the [LICENSE](./LICENSE) file for the full text.
