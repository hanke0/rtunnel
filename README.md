# rtunnel

[![Version](https://img.shields.io/badge/version-0.7.9-blue.svg)](https://github.com/hanke0/rtunnel/releases)
[![License](https://img.shields.io/badge/license-BSD%203--Clause-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)

A lightweight, secure tunneling tool written in Rust for exposing local servers behind NATs and firewalls to the public internet.

## Table of Contents

- [rtunnel](#rtunnel)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
    - [Download Pre-built Binaries](#download-pre-built-binaries)
    - [Build from Source](#build-from-source)
  - [Quick Start](#quick-start)
    - [Step 1: Generate Key Pairs](#step-1-generate-key-pairs)
    - [Step 2: Create Configuration File](#step-2-create-configuration-file)
    - [Step 3: Configure Server and Client](#step-3-configure-server-and-client)
    - [Step 4: Run the Server](#step-4-run-the-server)
    - [Step 5: Run the Client](#step-5-run-the-client)
  - [How It Works](#how-it-works)
  - [Use Cases](#use-cases)
  - [Testing](#testing)
  - [License](#license)

## Features

- **🔐 Secure Encryption**: Uses X25519 for key exchange, Ed25519 for authentication, and AES-256-GCM for data encryption
- **⚙️ Simple Configuration**: TOML-based configuration file with example generator
- **🔌 Multiple Services**: Support for multiple tunnel services in a single configuration
- **📊 Connection Pooling**: Configurable connection limits and idle connection management
- **🌐 Cross-Platform**: Works on Unix (Linux, macOS, FreeBSD) and Windows systems
- **🛡️ Graceful Shutdown**: Handles signals (SIGINT, SIGTERM) for clean shutdown
- **🚀 High Performance**: Built with Rust and Tokio for efficient async I/O

## Installation

### Download Pre-built Binaries

Pre-built binaries are available for multiple platforms on the [releases page](https://github.com/hanke0/rtunnel/releases):

- Linux (x86_64, aarch64, riscv64)
- macOS (x86_64, aarch64)
- Windows (x86_64)
- FreeBSD (x86_64)

### Build from Source

**Prerequisites:**
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- Cargo (comes with Rust)

**Build:**

```bash
git clone https://github.com/hanke0/rtunnel.git
cd rtunnel
cargo build --release
```

The binary will be located at `target/release/rtunnel`.

## Quick Start

To use `rtunnel`, you need:
- A **server** with a public IP address
- A **client** device behind a NAT/firewall with services to expose

### Step 1: Generate Key Pairs

Generate key pairs for both the server and client:

```bash
# On the server
rtunnel generate-key

# On the client
rtunnel generate-key
```

Each command will output a `private_key` and `public_key`. Save these securely.

### Step 2: Create Configuration File

Generate an example configuration:

```bash
rtunnel example-config > rtunnel.toml
```

**Security Note**: On Unix systems, ensure your config file has restricted permissions:

```bash
chmod 600 rtunnel.toml
```

### Step 3: Configure Server and Client

Edit `rtunnel.toml` to:
- Add the server's key pair in the `[[servers]]` section
- Add the client's public key to `client_public_key` in the server section
- Add the client's key pair in the `[[clients]]` section
- Add the server's public key to `server_public_key` in the client section
- Configure `server_address` (where the client connects to)
- Configure `listen` (where the server listens)
- Set up `services` with `bind_to` (public address) and `connect_to` (local service address)
- Configure `allowed_addresses` for security
- See the [rtunnel.toml](rtunnel.toml) for full config example.

### Step 4: Run the Server

On your public server:

```bash
rtunnel server --config rtunnel.toml
```

### Step 5: Run the Client

On your local machine:

```bash
rtunnel client --config rtunnel.toml
```

## How It Works

1. **Client-Server Connection**: The client establishes an encrypted connection to the server using X25519 key exchange and Ed25519 authentication.

2. **Service Mapping**: The server binds to public addresses (e.g., `0.0.0.0:8001`) and forwards traffic through the encrypted tunnel.

3. **Traffic Routing**: When a connection is made to the server's public address:
   - The server accepts the connection
   - It sends a connect message through the encrypted tunnel to the client
   - The client connects to the configured local service
   - Data is bidirectionally relayed through the encrypted tunnel

4. **Security**: All traffic is encrypted using AES-256-GCM, and clients can only connect to addresses specified in `allowed_addresses`.

## Use Cases

- **Local Development**: Expose local web servers for testing or demos
- **Remote Access**: Access services on home networks (SSH, web servers, databases)
- **IoT Devices**: Expose services running on devices behind NAT
- **Microservices**: Tunnel between services in different networks
- **Bypass Firewalls**: Securely tunnel through restrictive network policies

## Testing

Run the integration tests:

```bash
cargo test
```

For verbose test output:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

## License

BSD 3-Clause License

See the [LICENSE](LICENSE.txt) file for details.
