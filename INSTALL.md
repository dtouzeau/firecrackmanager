# FireCrackManager Installation Guide

## Prerequisites

- Debian/Ubuntu Linux (x86_64)
- Root access
- KVM support (`/dev/kvm` must exist)
- Network capabilities for TAP/Bridge devices

## Method 1: Install from .deb Package (Recommended)

```bash
# Download the package
wget https://github.com/dtouzeau/firecrackmanager/releases/download/1.0.1/firecrackmanager_1.0.1_amd64.deb

# Install
sudo dpkg -i firecrackmanager_1.0.1_amd64.deb

# Run setup wizard (downloads Firecracker, creates default network)
sudo firecrackmanager -setup

# Start the service
sudo systemctl start firecrackmanager
sudo systemctl enable firecrackmanager
```

## Method 2: Manual Binary Installation

### Step 1: Download the Binary

```bash
# Download firecrackmanager binary
compile the binary
chmod +x /usr/local/bin/firecrackmanager
```

### Step 2: Create Directories

```bash
mkdir -p /etc/firecrackmanager
mkdir -p /var/lib/firecrackmanager/kernels
mkdir -p /var/lib/firecrackmanager/rootfs
mkdir -p /var/lib/firecrackmanager/sockets
mkdir -p /var/lib/firecrackmanager/snapshots
mkdir -p /var/lib/firecrackmanager/disks
mkdir -p /var/log/firecrackmanager
```

### Step 3: Create Configuration File

```bash
cat > /etc/firecrackmanager/settings.json << 'EOF'
{
    "listen_port": 8080,
    "listen_address": "0.0.0.0",
    "data_dir": "/var/lib/firecrackmanager",
    "database_path": "/var/lib/firecrackmanager/firecrackmanager.db",
    "log_file": "/var/log/firecrackmanager/firecrackmanager.log",
    "pid_file": "/var/run/firecrackmanager.pid"
}
EOF
```

### Step 4: Create Systemd Service

```bash
cat > /etc/systemd/system/firecrackmanager.service << 'EOF'
[Unit]
Description=FireCrackManager - MicroVM Management Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/firecrackmanager -config /etc/firecrackmanager/settings.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
```

### Step 5: Run Setup Wizard

```bash
sudo firecrackmanager -setup
```

The setup wizard will:
- Check system prerequisites
- Download and install Firecracker binaries
- Configure KVM permissions
- Enable IP forwarding
- Set up NAT rules
- Download default kernel and rootfs
- Create default network (192.168.100.0/24)

### Step 6: Start the Service

```bash
sudo systemctl start firecrackmanager
sudo systemctl enable firecrackmanager
```

## Access the Web Interface

Open your browser and navigate to:

```
http://<server-ip>:8080
```

**Default credentials:**
- Username: `admin`
- Password: `admin`

## Verify Installation

```bash
# Check service status
systemctl status firecrackmanager

# Check logs
tail -f /var/log/firecrackmanager/firecrackmanager.log

# Verify Firecracker is installed
/usr/sbin/firecracker --version
```

## Firewall Configuration

If you have a firewall enabled, allow port 8080:

```bash
# UFW
sudo ufw allow 8080/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

## Uninstallation

### From .deb package:
```bash
sudo dpkg -r firecrackmanager
# To also remove data:
sudo dpkg -P firecrackmanager
```

### Manual uninstall:
```bash
sudo systemctl stop firecrackmanager
sudo systemctl disable firecrackmanager
sudo rm /usr/local/bin/firecrackmanager
sudo rm /etc/systemd/system/firecrackmanager.service
sudo rm -rf /etc/firecrackmanager
sudo rm -rf /var/lib/firecrackmanager
sudo rm -rf /var/log/firecrackmanager
sudo systemctl daemon-reload
```
