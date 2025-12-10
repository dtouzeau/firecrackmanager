# FireCrackManager

A MicroVM management daemon for [Firecracker](https://firecracker-microvm.github.io/). 
FireCrackManager is a part of Artica appliance.

It provides a REST API and web-based UI for managing virtual machines, networks, kernel images, and root filesystems.

## Features

### Virtual Machine Management
- Create, start, stop, and delete MicroVMs
- Configure vCPU, memory, kernel arguments, and DNS servers
- Real-time VM status monitoring with reachability checks
- Serial console access via WebSocket
- **Autorun**: Automatically start designated VMs when FireCrackManager starts

### Snapshots
- Create full and differential snapshots of running VMs
- List, restore, and delete snapshots
- Preserve VM state for quick recovery

### Disk Management
- Attach additional virtual disks to VMs
- Automatic ext4 filesystem formatting
- Automatic fstab configuration for persistent mounts
- Support for multiple disks per VM

### VM Import/Export
- Export VMs as `.fcrack` archives (virtual appliance format)
- Import `.fcrack` files to create new VMs
- Duplicate existing VMs with all configurations

### Network Management
- Create isolated virtual networks with custom subnets
- Automatic TAP device and bridge creation
- NAT support for internet connectivity
- IP allocation and MAC address generation

### Kernel & RootFS Management
- Download kernel images from URLs
- Download or create root filesystem images
- Upload custom images via web interface
- Set default kernel for new VMs

### User & Group Management
- Multi-user support with role-based access (admin/user)
- **Privilege Groups**: Assign users to groups with specific permissions
- Group-level VM access control (start, stop, console, edit, snapshot, disk)
- Session-based authentication