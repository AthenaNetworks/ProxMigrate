# Proxmigrate

A powerful, cross-platform tool for migrating virtual machines between Proxmox VE servers.

## Features

- 🚀 **Multi-Environment Support**: Configure multiple Proxmox servers as both sources and targets
- 🔐 **Secure Authentication**: Uses Proxmox API tokens and SSH key authentication
- 🌐 **Cross-Platform**: Builds for macOS, Linux, and Windows
- 📦 **Self-Contained**: SSH keys and configuration travel with the binary
- ⚡ **Fast Transfers**: Direct server-to-server file transfers via SSH/SCP
- 🔄 **VM Type Support**: Handles both QEMU VMs and LXC containers
- 🎯 **Simple Usage**: Clean command-line interface with named environments

## Quick Start

### 1. Setup Configuration

Copy the example configuration and customize it:

```bash
cp config.json.example config.json
```

Edit `config.json` and replace `YOUR_TOKEN_SECRET_HERE` with your actual Proxmox API token secrets.

### 2. Generate SSH Keys

Generate SSH keys for server authentication:

```bash
ssh-keygen -t rsa -b 4096 -f ./proxmigrate_key -N "" -C "proxmigrate-tool"
```

### 3. Deploy Public Key

Add the public key to all your Proxmox servers:

```bash
# Copy the public key content
cat proxmigrate_key.pub

# On each Proxmox server, add to ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
```

### 4. Run Migration

```bash
./proxmigrate --source=ara-asp-pxnode1 --target=ara-asp-pve15 --vmid=109
```

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases](../../releases) page.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/proxmigrate.git
cd proxmigrate

# Build for all platforms
./build.sh

# Or build for current platform only
make dev
```

## Usage

### Basic Migration

```bash
proxmigrate --source=SOURCE_NAME --target=TARGET_NAME --vmid=VM_ID
```

### Available Options

- `--source`: Source environment name from config
- `--target`: Target environment name from config  
- `--vmid`: VM ID to migrate
- `--config`: Path to configuration file (optional, auto-detected)
- `--version`: Show version information

### Examples

```bash
# Migrate VM 109 from pxnode1 to pve15
./proxmigrate --source=ara-asp-pxnode1 --target=ara-asp-pve15 --vmid=109

# Migrate VM 200 from pve16 to pxnode3
./proxmigrate --source=ara-asp-pve16 --target=ara-asp-pxnode3 --vmid=200

# Show version
./proxmigrate --version
```

## Configuration

The tool uses a JSON configuration file that defines your Proxmox environments:

```json
{
  "sources": {
    "ara-asp-pve15": {
      "host": "https://192.168.228.35:8006/",
      "user": "root@pam",
      "token_id": "root@pam!migration-tool",
      "token_secret": "your-token-secret",
      "insecure": true
    }
  },
  "targets": {
    "ara-asp-pve15": {
      "host": "https://192.168.228.35:8006/",
      "user": "root@pam", 
      "token_id": "root@pam!migration-tool",
      "token_secret": "your-token-secret",
      "node": "ara-asp-pve15",
      "storage": "tier1",
      "insecure": true
    }
  },
  "ssh": {
    "user": "root",
    "key_path": "./proxmigrate_key"
  }
}
```

### Configuration Fields

#### Sources/Targets
- `host`: Proxmox server URL with port
- `user`: Proxmox user (usually `root@pam`)
- `token_id`: API token ID
- `token_secret`: API token secret
- `insecure`: Skip TLS verification (for self-signed certs)

#### Targets Only
- `node`: Target Proxmox node name
- `storage`: Target storage name

#### SSH
- `user`: SSH user for server connections
- `key_path`: Path to SSH private key

## Migration Process

The tool performs a 4-step migration:

1. **Fetch VM Config**: Retrieves VM configuration from source server
2. **Export VM**: Creates backup using Proxmox vzdump
3. **Transfer Backup**: Copies backup file via SSH/SCP
4. **Import VM**: Restores VM on target server with new VMID
5. **Cleanup**: Removes temporary backup files

## Development

### Build System

```bash
# Build all platforms
make build

# Development build
make dev

# Clean build artifacts  
make clean

# Run tests
make test

# Format code
make fmt

# Tidy dependencies
make tidy
```

### Project Structure

```
proxmigrate/
├── main.go              # Main application code
├── config.json.example  # Configuration template
├── build.sh            # Unix build script
├── build.bat           # Windows build script
├── Makefile            # Build automation
├── go.mod              # Go module definition
└── README.md           # This file
```

## Requirements

- Go 1.19+ (for building from source)
- Proxmox VE 6.0+ servers
- SSH access to Proxmox servers
- API tokens configured on Proxmox servers

## Security Notes

- 🔐 **Never commit SSH keys or config files with secrets to version control**
- 🛡️ **Use dedicated API tokens with minimal required permissions**
- 🔒 **Ensure SSH keys have proper permissions (600 for private key)**
- 🌐 **Consider using proper TLS certificates instead of `insecure: true`**

## Troubleshooting

### Common Issues

**SSH Connection Failed**
- Verify SSH key is deployed to all servers
- Check SSH key permissions (600 for private key)
- Ensure SSH user has proper access

**API Authentication Failed**
- Verify API token ID and secret are correct
- Check token permissions in Proxmox
- Ensure token is not expired

**Storage Not Found**
- Verify storage name exists on target server
- Check storage permissions
- Ensure storage has sufficient space

### Debug Mode

For verbose output, you can modify the source code to enable debug logging or run with:

```bash
# Check configuration loading
./proxmigrate --source=test --target=test --vmid=999
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

---

**Made with ❤️ for the Proxmox community**
