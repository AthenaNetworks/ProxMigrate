# 🚀 Proxmigrate - Interactive Proxmox VM Migration Tool

A powerful, user-friendly command-line tool for migrating virtual machines between Proxmox VE servers with beautiful interactive prompts and robust file transfer capabilities.

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

### 🎯 Interactive Experience
- **Beautiful CLI Prompts**: Interactive server and VM selection with search capabilities
- **Smart VM Discovery**: Automatically fetches and displays VMs from source servers
- **Rich VM Display**: Shows VM status (🔴 stopped, 🟢 running), names, types, and nodes
- **Node-Filtered Selection**: Only shows VMs from the selected source node to prevent errors
- **Backward Compatible**: Works with both interactive prompts and traditional flags

### 🔧 Robust Migration
- **Multi-Environment Support**: Configure multiple source and target Proxmox environments
- **QEMU & LXC Support**: Migrate both virtual machines and containers
- **Configurable Storage**: Support for any Proxmox storage type (local, NFS, Ceph, etc.)
- **Secure Transfers**: SSH-based file transfers with automatic key management
- **API Authentication**: Uses Proxmox API tokens for secure authentication
- **Progress Monitoring**: Real-time progress updates during export and import

### 🛠️ Advanced Features
- **Connectivity Testing**: Built-in connection testing for troubleshooting
- **Host Discovery**: List all configured environments with their roles
- **Debug Logging**: Comprehensive debug output for troubleshooting
- **Cross-Platform**: Builds for Linux, macOS, and Windows
- **Automatic Cleanup**: Removes temporary files and SSH keys securely

## 📋 Prerequisites

- **Go 1.23+** (for building from source)
- **SSH Access** to both source and target Proxmox servers
- **API Tokens** configured on Proxmox servers with appropriate permissions
- **Network Connectivity** between source and target servers
- **Storage Space** on target server for VM backups

## 🚀 Quick Start

### 1. Download or Build

**Option A: Download Pre-built Binary**
```bash
# Download from releases page (recommended)
wget https://github.com/your-repo/proxmigrate/releases/latest/download/proxmigrate-linux-amd64.tar.gz
tar -xzf proxmigrate-linux-amd64.tar.gz
cd proxmigrate-linux-amd64
```

**Option B: Build from Source**
```bash
git clone https://github.com/your-repo/proxmigrate.git
cd proxmigrate
go build -o proxmigrate
```

### 2. Configure Environments

First, copy the example configuration and customize it (the setup script needs this):

```bash
cp config.json.example config.json
# Edit config.json with your server details
```

### 3. Setup SSH Keys and Deploy

**Option A: Use the automated setup script (recommended)**

The script will generate SSH keys if they don't exist AND deploy them to all servers in your config:

```bash
./setup-proxmox.sh
```

**Option B: Manual setup**

```bash
# Generate SSH key pair manually
ssh-keygen -t rsa -b 4096 -f proxmigrate_key -N ""

# Then copy to each server manually
ssh-copy-id -i proxmigrate_key.pub root@your-proxmox-server
# Repeat for all servers in your configuration
```

### 5. Test Connectivity

```bash
./proxmigrate --test --source=prod --target=backup
```

### 6. Start Migrating!

```bash
# Interactive mode (recommended for new users)
./proxmigrate

# Or use flags for automation
./proxmigrate --source=prod --target=backup --vmid=100
```

## ⚙️ Configuration

### Configuration File Structure

Create a `config.json` file with your Proxmox environments:

```json
{
  "sources": {
    "prod-cluster": {
      "host": "https://pve-prod.company.com:8006",
      "token_id": "proxmigrate@pve!migration",
      "token_secret": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "backup_storage": "migration",
      "insecure": false
    },
    "dev-cluster": {
      "host": "https://pve-dev.company.com:8006",
      "token_id": "proxmigrate@pve!migration",
      "token_secret": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
      "backup_storage": "local",
      "insecure": true
    }
  },
  "targets": {
    "backup-cluster": {
      "host": "https://pve-backup.company.com:8006",
      "token_id": "proxmigrate@pve!restore",
      "token_secret": "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
      "node": "pve-backup-01",
      "storage": "ceph-tier1",
      "backup_storage": "migration",
      "insecure": false
    }
  },
  "ssh": {
    "user": "root",
    "key_path": "./proxmigrate_key"
  }
}
```

### Configuration Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|----------|
| `host` | Proxmox server URL with port | ✅ | - |
| `token_id` | API token ID (format: `user@realm!tokenname`) | ✅ | - |
| `token_secret` | API token secret | ✅ | - |
| `backup_storage` | Storage for VM backups | ✅ | `"local"` |
| `node` | Target node name (targets only) | ✅ | - |
| `storage` | Target VM storage (targets only) | ✅ | - |
| `insecure` | Skip TLS certificate validation | ❌ | `false` |

### Storage Types and Paths

Proxmigrate automatically handles different storage types:

- **`"local"`**: Uses `/var/lib/vz/dump/`
- **Other storages**: Uses `/mnt/pve/STORAGE_NAME/dump/`

Examples:
- `"backup_storage": "local"` → `/var/lib/vz/dump/`
- `"backup_storage": "migration"` → `/mnt/pve/migration/dump/`
- `"backup_storage": "nfs-backups"` → `/mnt/pve/nfs-backups/dump/`

## 🎮 Usage Modes

### Interactive Mode (Recommended)

Simply run the tool without flags for a guided experience:

```bash
./proxmigrate
```

**Interactive Flow:**
1. 🖥️ **Select Source Server**: Choose from configured sources
2. 🎯 **Select Target Server**: Choose from configured targets  
3. 📋 **Select VM**: Browse VMs from the source server with search
4. ✅ **Confirm Migration**: Review settings before proceeding
5. 🚀 **Watch Progress**: Monitor the migration in real-time

**Interactive VM Selection Features:**
- **Rich Display**: `🔴 VM 138: test-migrate-vm [stopped] on pve-node-01`
- **Search**: Type to filter by VM ID, name, or status
- **Node Filtering**: Only shows VMs from the selected source server
- **Status Icons**: 🔴 stopped, 🟢 running, ⏸️ paused, etc.

### Command-Line Mode

For automation and scripting:

```bash
# Basic migration
./proxmigrate --source=prod --target=backup --vmid=100

# With custom config file
./proxmigrate --config=/path/to/config.json --source=prod --target=backup --vmid=100

# Test connectivity
./proxmigrate --test --source=prod --target=backup

# List configured environments
./proxmigrate --list

# Show version
./proxmigrate --version
```

### Command-Line Flags

| Flag | Description | Example |
|------|-------------|----------|
| `--config` | Path to configuration file | `--config=/etc/proxmigrate.json` |
| `--source` | Source environment name | `--source=production` |
| `--target` | Target environment name | `--target=backup-site` |
| `--vmid` | VM ID to migrate | `--vmid=100` |
| `--test` | Test connectivity only | `--test` |
| `--list` | List configured hosts | `--list` |
| `--version` | Show version information | `--version` |

## 🔄 Migration Process

Proxmigrate performs a comprehensive 4-step migration:

### Step 1: 🔍 Fetch VM Configuration
- Connects to source Proxmox API
- Locates the VM across all nodes in the cluster
- Retrieves complete VM configuration
- Validates VM exists and is accessible

### Step 2: 📦 Export VM
- Creates a compressed backup using `vzdump`
- Supports both QEMU VMs and LXC containers
- Uses configurable backup storage location
- Shows real-time progress with transfer rates
- Handles large VMs efficiently with streaming

### Step 3: 🚚 Transfer Backup
- Establishes secure SSH connections to both servers
- Copies SSH key to source server temporarily
- Performs direct server-to-server transfer via SCP
- Shows transfer progress with file size and speed
- Automatically cleans up temporary SSH keys

### Step 4: 📥 Import VM
- Finds next available VM ID on target server
- Restores VM using Proxmox restore API
- Configures VM with target storage settings
- Shows import progress with detailed status
- Cleans up backup files after successful import

## 🔧 Advanced Usage

### Multiple Environment Management

Proxmigrate excels at managing multiple Proxmox environments:

```bash
# List all configured environments
./proxmigrate --list
```

Output:
```
Configured Proxmox Hosts:

ara-asp-pve15     [source,target]  192.168.228.35:8006
ara-asp-pve16     [source,target]  192.168.228.36:8006
ara-asp-pxnode1   [source,target]  192.168.228.50:8006
ara-asp-pxnode2   [source,target]  192.168.228.51:8006

Summary: 4 total hosts (4 sources, 4 targets)
```

### Connectivity Testing

Before performing migrations, test your setup:

```bash
./proxmigrate --test --source=prod --target=backup
```

Output:
```
Testing connectivity to source and target servers...

Source Server (prod):
  API Connection: ✓ Connected successfully
  API Authentication: ✓ Token valid
  SSH Connection: ✓ Connected successfully
  Server Version: pve-manager/8.0.3

Target Server (backup):
  API Connection: ✓ Connected successfully
  API Authentication: ✓ Token valid
  SSH Connection: ✓ Connected successfully
  Server Version: pve-manager/8.0.3

✅ All connectivity tests passed!
```

### Automation and Scripting

Proxmigrate is perfect for automation:

```bash
#!/bin/bash
# Automated backup script

VMS=(100 101 102 103)
SOURCE="production"
TARGET="backup-site"

for vm in "${VMS[@]}"; do
    echo "Migrating VM $vm..."
    ./proxmigrate --source="$SOURCE" --target="$TARGET" --vmid="$vm"
    if [ $? -eq 0 ]; then
        echo "✅ VM $vm migrated successfully"
    else
        echo "❌ VM $vm migration failed"
        exit 1
    fi
done

echo "🎉 All VMs migrated successfully!"
```

## 🔐 Security & Best Practices

### API Token Setup

1. **Create dedicated user for migrations:**
```bash
# On each Proxmox server
pveum user add proxmigrate@pve --comment "VM Migration Tool"
```

2. **Create API tokens with appropriate permissions:**
```bash
# Create token
pveum user token add proxmigrate@pve migration --privsep=0

# Grant necessary permissions
pveum acl modify / --users proxmigrate@pve --roles Administrator
```

3. **Use least-privilege principle in production:**
```bash
# More restrictive permissions for production
pveum role add VMigrator --privs "VM.Allocate,VM.Migrate,VM.Monitor,Datastore.Allocate"
pveum acl modify / --users proxmigrate@pve --roles VMigrator
```

### SSH Security

- **Use dedicated SSH keys**: The tool includes `proxmigrate_key` specifically for migrations
- **Restrict SSH access**: Configure SSH to only allow key-based authentication
- **Regular key rotation**: Regenerate SSH keys periodically
- **Monitor access**: Review SSH logs for migration activities

### Network Security

- **Firewall rules**: Only allow necessary ports (22 for SSH, 8006 for Proxmox API)
- **VPN/Private networks**: Use private networks for server-to-server communication
- **Certificate validation**: Use `"insecure": false` in production environments

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Authentication Problems

**❌ Error: `API token ID and secret are required`**
```bash
# Solution: Check your config.json format
{
  "sources": {
    "myserver": {
      "token_id": "user@realm!tokenname",  # ← Must include @realm!
      "token_secret": "your-secret-here"
    }
  }
}
```

**❌ Error: `Permission denied (publickey,password)`**
```bash
# Solution: Deploy SSH key properly
ssh-copy-id -i proxmigrate_key.pub root@your-server

# Or use the setup script
./setup-proxmox.sh
```

#### Network Connectivity

**❌ Error: `connection refused`**
```bash
# Check if Proxmox API is accessible
curl -k https://your-server:8006/api2/json/version

# Check SSH connectivity
ssh -i proxmigrate_key root@your-server
```

**❌ Error: `certificate verify failed`**
```json
// Temporary fix: Add to config.json
{
  "sources": {
    "myserver": {
      "insecure": true  // ← Only for self-signed certificates
    }
  }
}
```

#### Storage Issues

**❌ Error: `no backup files found`**
```bash
# Check backup storage configuration
# Ensure backup_storage matches your Proxmox storage name
{
  "backup_storage": "migration"  # ← Must match Proxmox storage ID
}
```

**❌ Error: `failed to create target directory`**
```bash
# Check storage permissions on target server
ssh root@target-server "ls -la /mnt/pve/migration/"

# Fix permissions if needed
ssh root@target-server "chown root:root /mnt/pve/migration/dump && chmod 755 /mnt/pve/migration/dump"
```

#### VM-Specific Issues

**❌ Error: `VM not found`**
- VM might be on a different node than expected
- Use interactive mode to see all available VMs
- Check VM ID is correct: `qm list` on source server

**❌ Error: `insufficient storage space`**
```bash
# Check available space on target
ssh root@target "df -h /var/lib/vz"

# Check VM size before migration
qm config YOUR_VMID | grep -E "(virtio|scsi|ide).*size"
```

### Debug Mode

For detailed troubleshooting, the tool provides comprehensive debug output:

```bash
# Debug output is automatically shown during transfers
./proxmigrate --source=prod --target=backup --vmid=100
```

Look for debug lines like:
```
DEBUG: Executing SCP command: scp -o StrictHostKeyChecking=no...
DEBUG: Source path: /mnt/pve/migration/dump/vzdump-qemu-100-...
DEBUG: Target path: root@192.168.1.100:/mnt/pve/migration/dump/...
```

### Getting Help

1. **Check connectivity first**: `./proxmigrate --test --source=X --target=Y`
2. **List environments**: `./proxmigrate --list`
3. **Review logs**: Check Proxmox logs in `/var/log/pve/`
4. **Test manually**: Try SSH and API calls manually to isolate issues

## 🏗️ Building and Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/your-repo/proxmigrate.git
cd proxmigrate

# Install dependencies
go mod tidy

# Build for current platform
go build -o proxmigrate

# Build for all platforms
./build.sh
```

### Cross-Platform Builds

The included build script creates binaries for all major platforms:

```bash
./build.sh
```

Generates:
- `proxmigrate-linux-amd64.tar.gz`
- `proxmigrate-linux-arm64.tar.gz`
- `proxmigrate-darwin-amd64.tar.gz`
- `proxmigrate-darwin-arm64.tar.gz`
- `proxmigrate-windows-amd64.zip`

### Development Setup

```bash
# Install development dependencies
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run tests
go test ./...

# Run linter
golangci-lint run

# Format code
go fmt ./...
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** with tests
4. **Run the test suite**: `go test ./...`
5. **Submit a pull request**

### Code Style

- Follow standard Go formatting (`go fmt`)
- Add comments for exported functions
- Include tests for new features
- Update documentation as needed

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [promptui](https://github.com/manifoldco/promptui) - Beautiful interactive prompts
- [go-proxmox](https://github.com/luthermonson/go-proxmox) - Proxmox API client library
- Proxmox VE team for the excellent virtualization platform

---

**Made with ❤️ for the Proxmox community**

*For support, please open an issue on GitHub or check our troubleshooting section above.*
