# Netatalk Setup Progress - MacPro 2013

**Date:** January 12, 2026 (Updated with Soft-Seed Mode Configuration)  
**Netatalk Version:** 4.4.0 (origin/main: fe225c6b)  
**OS:** Ubuntu 25.10

## Overview

This document tracks the setup and configuration of Netatalk AFP server on the MacPro 2013 system.

**Major Update (January 12, 2026):** Successfully configured to work with jrouter's soft-seed mode. atalkd now runs as the seed router, and jrouter queries it for network configuration.

## Current Configuration (KNOWN GOOD - January 12, 2026)

### ✅ Working Configuration with Soft-Seed jrouter

**Configuration Summary:**
- **atalkd:** Seed router on enp12s0 @ 650.37
- **jrouter:** Soft-seed on enp11s0 @ 650.1
- **Status:** ✅ Both services coexisting, AFP shares visible

### atalkd Configuration

**File:** `/home/blake/code/machine-cfg/macpro2013/atalkd.conf`

```
# AppleTalk daemon configuration (netatalk 4.x)
# Interface configuration for enp12s0
# Configured as seed router (-router implies -seed)
# jrouter on enp11s0 runs in soft-seed mode and queries this for config
enp12s0 -router -phase 2 -net 650 -addr 650.37 -zone "netjibbing"
```

**Key Changes:**
- Added `-router` flag (makes atalkd the seed router)
- Static address: 650.37
- Network: 650 (explicitly configured)
- Zone: "netjibbing"

**Systemd Override:** `/etc/systemd/system/atalkd.service.d/override.conf`
```ini
[Unit]
# atalkd is now the seed router - no dependency on jrouter

[Service]
ExecStart=
ExecStart=/usr/local/sbin/atalkd -f /home/blake/code/machine-cfg/macpro2013/atalkd.conf
```

**Key Change:** Removed `After=jrouter.service` and `Requires=jrouter.service` since atalkd is now the seed.

### Verification

```bash
$ sudo systemctl status atalkd
● atalkd.service - Netatalk AppleTalk daemon
   Active: active (running)
   
$ nbplkup
macpro2013:AFPServer     650.37:128
macpro2013:netatalk      650.37:4
macpro2013:Workstation   650.37:4

$ getzones
netjibbing
(+ 27 AURP zones from jrouter peers)
```

---

## Completed Steps

### 1. Prerequisites Installation

All required dependencies were installed for Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --assume-yes --no-install-recommends \
  bison cmark-gfm cracklib-runtime flex libacl1-dev \
  libavahi-client-dev libcrack2-dev libcups2-dev libdb-dev \
  libdbus-1-dev libevent-dev libgcrypt20-dev libglib2.0-dev \
  libiniparser-dev libkrb5-dev libldap2-dev libmariadb-dev \
  libpam0g-dev libsqlite3-dev libtalloc-dev libtirpc-dev \
  libtracker-sparql-3.0-dev libwrap0-dev meson ninja-build \
  quota systemtap-sdt-dev tcpd tracker tracker-miner-fs
```

**Status:** ✅ All prerequisites installed and verified

**Note:** `libsqlite3-dev` is required for SQLite CNID backend support. `libmariadb-dev` is included for MySQL CNID backend support (optional, not used with SQLite default).

### 2. Source Code Setup

- **Repository:** `/home/blake/code/netatalk`
- **Branch:** main (updated to origin/main)
- **Commit:** `fe225c6b`

**Checkout command:**
```bash
git fetch origin pull/2577/head:pr-2577
git checkout pr-2577
```

**Status:** ✅ PR checked out successfully

### 3. Build Configuration

Build configured with the following options:

```bash
meson setup build \
  -Dbuildtype=release \
  -Dwith-appletalk=true \
  -Dwith-cups-pap-backend=true \
  -Dwith-dbus-sysconf-path=/usr/share/dbus-1/system.d \
  -Dwith-init-hooks=false \
  -Dwith-tests=true \
  -Dwith-testsuite=true \
  -Dwith-cnid-default-backend=sqlite
```

**Status:** ✅ Configuration successful

**Note:** Built with `with-cnid-default-backend = sqlite` to use SQLite as the default CNID backend (no external database server required).

### 4. Build and Installation

**Build:**
```bash
meson compile -C build
```

**Install:**
```bash
sudo meson install -C build
```

**Status:** ✅ Build completed (423 steps), installation successful

**CNID SQLite:** ✅ SQLite CNID backend built and set as the default CNID backend (verify with `meson configure build` -> `with-cnid-default-backend: sqlite`).

**Installed binaries:**
- `/usr/local/sbin/netatalk` - Main service controller
- `/usr/local/sbin/afpd` - AFP daemon
- `/usr/local/sbin/cnid_dbd` - CNID database daemon
- `/usr/local/sbin/atalkd` - AppleTalk daemon
- `/usr/local/sbin/papd` - Printer daemon

### 5. AppleTalk Kernel Modules

**Modules loaded:**
- `appletalk` (53,248 bytes)
- `psnap` (12,288 bytes) - dependency
- `llc` (16,384 bytes) - dependency

**Load commands:**
```bash
sudo modprobe psnap
sudo modprobe appletalk
```

**Status:** ✅ Modules loaded successfully

**Note:** To load automatically at boot, add to `/etc/modules`:
```
psnap
appletalk
```

### 6. Systemd Configuration

**Custom config file location:**
- Config file: `/home/blake/code/machine-cfg/macpro2013/afp.conf`
- Systemd override: `/etc/systemd/system/netatalk.service.d/override.conf`

**Override file contents:**
```ini
[Unit]
Requires=atalkd.service

[Service]
ExecStart=
ExecStart=/usr/local/sbin/netatalk -F /home/blake/code/machine-cfg/macpro2013/afp.conf
```

**Note:** The `Requires=atalkd.service` ensures that netatalk will not start if atalkd fails to start, providing stronger dependency than the default `After=` only dependency from the template.

**Status:** ✅ Systemd configured to use custom config file and require atalkd

**Service management:**
```bash
# Start service
sudo systemctl start netatalk

# Enable at boot
sudo systemctl enable netatalk

# Check status
sudo systemctl status netatalk

# Reload after config changes
sudo systemctl daemon-reload
sudo systemctl restart netatalk
```

### 7. Configuration File

**Location:** `/home/blake/code/machine-cfg/macpro2013/afp.conf`

**Current configuration:**
```ini
[Global]
; Global server settings
appletalk = yes
uam list = uams_randnum.so uams_guest.so
ddp zone = netjibbing
guest account = blake
log level = default:maxdebug

[MacPro]
path = /files/MacPro
cnid scheme = sqlite
guest ok = yes
read only = no
unix priv = no
file perm = 0666
directory perm = 0777
```

**Note:** `cnid scheme = sqlite` is optional since SQLite is the default CNID backend, but explicitly specifying it is recommended for clarity.

**Status:** ✅ Config file exists and is readable

### 8. Password File Setup

**Password file location:** `/usr/local/etc/afppasswd`

**Status:** ✅ Password file created (initialized with `afppasswd -c`)

**Note:** Guest access is configured to use the `blake` account for filesystem-level permissions.

### 9. AppleTalk Configuration (Current: Seed Router Mode)

**atalkd.conf location:** `/home/blake/code/machine-cfg/macpro2013/atalkd.conf`

**Current Configuration (January 12, 2026 - Seed Router):**
```
enp12s0 -router -phase 2 -net 650 -addr 650.37 -zone "netjibbing"
```

**Key Features:**
- `-router` flag: Makes atalkd a seed router (implies `-seed`)
- Static address: 650.37
- Network: 650 (explicitly configured, not auto-detect)
- Zone: "netjibbing"
- Interface: enp12s0 (dedicated, separate from jrouter on enp11s0)

**Systemd override:** `/etc/systemd/system/atalkd.service.d/override.conf`
```ini
[Unit]
# atalkd is now the seed router - no dependency on jrouter

[Service]
ExecStart=
ExecStart=/usr/local/sbin/atalkd -f /home/blake/code/machine-cfg/macpro2013/atalkd.conf
```

**Important:** atalkd is now the seed router. jrouter runs in soft-seed mode and queries atalkd for network configuration via ZIP GetNetInfo protocol.

**Status:** ✅ AppleTalk daemon configured and running as seed router
- Network: 650 (seed router for this network)
- Address: 650.37 (static, authoritative)
- Zone: netjibbing (default zone for network 650)
- Interface: enp12s0 (dedicated, 192.168.0.214)
- Role: Seed router (jrouter queries this for config)

**Interface Separation:**
- **atalkd/netatalk:** Uses `enp12s0` (192.168.0.214) - Seed router
- **jrouter:** Uses `enp11s0` (192.168.0.212) - Soft-seed router (queries atalkd)

**Benefits of Interface Separation:**
1. No packet capture conflicts - each service captures packets on its own interface
2. Network isolation - services are physically separated at the network layer
3. Simplified troubleshooting - issues with one service don't affect the other's network interface
4. Better performance - no competition for packet capture resources

**Service management:**
```bash
# Start service (atalkd starts independently as seed router)
sudo systemctl start atalkd

# Enable at boot
sudo systemctl enable atalkd

# Check status
sudo systemctl status atalkd

# Verify atalkd is seed router
sudo systemctl status atalkd | grep -i "seed\|router"
```

**Startup Order (Reversed from Previous Configuration):**
1. `atalkd.service` starts first (seed router for network 650)
2. `jrouter.service` starts after atalkd is ready (soft-seed, queries atalkd)
3. `netatalk.service` starts after atalkd is ready (AFP server, requires atalkd)

**Service Dependencies:**
- `atalkd.service`: No dependency on jrouter (independent seed router)
- `jrouter.service`: `After=atalkd.service`, `Requires=atalkd.service` (soft-seed needs seed)
- `netatalk.service`: `After=atalkd.service`, `Requires=atalkd.service` (AFP needs AppleTalk)

### Historical Configuration Notes

**Previous Configuration (Pre-Soft-Seed, January 2-11, 2026):**
```
enp12s0 -phase 2 -net 650 -addr 650.37 -zone "netjibbing"
```
- atalkd was a regular node (no `-router` flag)
- jrouter was the seed router on enp11s0
- Issue: atalkd showed "ready 0/0/0" and failed to respond to NBP queries
- Problem: atalkd's implementation as non-router on same L2 as seed had bugs

**Solution (January 12, 2026):**
- Implemented soft-seed mode in jrouter
- Reversed roles: atalkd as seed (`-router`), jrouter as soft-seed
- Result: Both services coexist successfully

### 10. Guest Access Configuration

**Status:** ✅ Guest access configured and working

**Configuration details:**
- Guest account: `blake` (for filesystem-level permissions)
- Guest UAM: `uams_guest.so` enabled in Global section
- Volume access: MacPro volume allows guest access with read-write permissions
- Permission model: `unix priv = no` for simplified guest permission handling
- File permissions: 0666 (read-write for all)
- Directory permissions: 0777 (read-write-execute for all)

**Verification:**
- Guest users can connect and see volumes
- Read-write access working correctly
- Both AFP/TCP and AFP/AppleTalk protocols supported

## Optional: Password-Based Authentication

If you want to add password-based authentication in addition to guest access:

**Option A: Add user to password file**
```bash
# Interactive (will prompt for password)
sudo afppasswd -a blake

# Non-interactive (set password directly)
sudo afppasswd -a -w "password_here" blake
```

**Option B: Update config for password authentication**

If using password-based authentication, update `uam list` in `afp.conf`:

**Simple password:**
```ini
uam list = uams_randnum.so uams_guest.so uams_passwd.so
```

**Encrypted password (recommended):**
```ini
uam list = uams_randnum.so uams_guest.so uams_dhx_passwd.so
```

## File Locations Summary

| Item | Location |
|------|----------|
| AFP config file | `/home/blake/code/machine-cfg/macpro2013/afp.conf` |
| atalkd config file | `/home/blake/code/machine-cfg/macpro2013/atalkd.conf` |
| atalkd service override | `/etc/systemd/system/atalkd.service.d/override.conf` |
| Password file | `/usr/local/etc/afppasswd` |
| Systemd service | `/usr/lib/systemd/system/netatalk.service` |
| Systemd override | `/etc/systemd/system/netatalk.service.d/override.conf` |
| Source code | `/home/blake/code/netatalk` |
| Build directory | `/home/blake/code/netatalk/build` |

## Available UAM Modules

Located in `/usr/local/lib/x86_64-linux-gnu/netatalk/`:
- `uams_randnum.so` - Random number authentication (currently in use)
- `uams_passwd.so` - Simple password authentication
- `uams_dhx_passwd.so` - Encrypted password authentication (DHX)
- `uams_dhx2_passwd.so` - Encrypted password authentication (DHX2)
- `uams_pam.so` - PAM authentication
- `uams_guest.so` - Guest access
- `uams_gss.so` - GSSAPI/Kerberos authentication

## Current Status

✅ **AppleTalk:** Configured and working as seed router
- atalkd service running on network 650, address 650.37 (seed router configuration)
- Zone: netjibbing (default zone)
- Role: Seed router (jrouter queries this for network config)
- AFP server advertising on AppleTalk: `macpro2013:AFPServer@netjibbing` on `650.37:128`
- Services registered: `macpro2013:AFPServer`, `macpro2013:netatalk`, `macpro2013:Workstation`
- Interface: enp12s0 (192.168.0.214) - dedicated, separate from jrouter
- jrouter: Soft-seed router at 650.1 on enp11s0, queries atalkd for config

✅ **AFP/TCP:** Configured and working
- Listening on 192.168.0.214:548
- Zeroconf registration enabled

✅ **Guest Access:** Configured and working
- Guest users can connect and access MacPro volume
- Read-write access enabled
- Guest account uses `blake` for filesystem permissions

✅ **Services:** Both atalkd and netatalk services enabled and running

✅ **CNID/SQLite:** SQLite backend built and enabled as the default CNID backend (verified at build time). SQLite stores the CNID database locally in each volume directory, requiring no external database server.

✅ **Coexistence with jrouter:** Successfully configured with soft-seed mode
- atalkd on enp12s0 (192.168.0.214) - Seed router for network 650
- jrouter on enp11s0 (192.168.0.212) - Soft-seed mode, queries atalkd
- Both services working correctly on the same AppleTalk network (650)
- Clients can see both the zone list (via AURP from jrouter) and the Netatalk share
- Interface separation provides isolation and prevents packet capture conflicts

## Verification and Troubleshooting

### Checking AppleTalk Service Registration

Use these commands to verify that the Netatalk share is visible on the AppleTalk network:

**1. Look up the specific AFPServer:**
```bash
sudo nbplkup "macpro2013:AFPServer"
```
**Expected output:** `macpro2013:AFPServer  650.37:128`

**2. Look up all AFPServer services:**
```bash
sudo nbplkup "AFPServer"
```
Lists all AFP servers registered on the AppleTalk network.

**3. Look up all services in the local zone:**
```bash
sudo nbplkup "*"
```
Displays all AppleTalk services registered in the current zone.

**4. List all available zones:**
```bash
sudo getzones
```
Shows all AppleTalk zones visible on the network.

**5. Look up services with verbose output:**
```bash
sudo nbplkup -s "*"
```
Provides detailed information about all services.

**6. Check Netatalk logs for AppleTalk registration:**
```bash
sudo journalctl -u netatalk | grep -i "AFPServer\|started on"
```
Shows log entries related to AFP server registration on AppleTalk.

**7. View recent Netatalk logs:**
```bash
sudo journalctl -u netatalk --since "10 minutes ago" --no-pager
```
Displays recent Netatalk service logs for troubleshooting.

**8. Check atalkd service status:**
```bash
sudo systemctl status atalkd
```
Verifies that the AppleTalk daemon is running correctly.

**9. Check Netatalk service status:**
```bash
sudo systemctl status netatalk
```
Verifies that the Netatalk service is running correctly.

**10. Restart Netatalk services (if share not visible):**
```bash
# Restart both services to refresh NBP registration
sudo systemctl restart atalkd
sudo systemctl restart netatalk

# Verify NBP registration
sudo nbplkup "macpro2013:AFPServer"
```

**11. Check interface configuration:**
```bash
# Verify atalkd interface
ip link show enp12s0

# Verify interface has IP address
ip addr show enp12s0
```

**12. View detailed Netatalk logs:**
```bash
# View atalkd logs
sudo journalctl -u atalkd -n 50 --no-pager

# View netatalk/afpd logs
sudo journalctl -u netatalk -n 50 --no-pager

# Filter for specific events
sudo journalctl -u netatalk | grep -i "AFPServer\|started on\|register"
```

### Service Information

When properly registered, the AFP server should appear as:
- **Service name:** `macpro2013:AFPServer`
- **AppleTalk address:** `650.37:128`
- **Zone:** `netjibbing`
- **Registered services:** `macpro2013:AFPServer`, `macpro2013:netatalk`, `macpro2013:Workstation`

## Troubleshooting Notes

### Share Not Visible on Client

If the Netatalk share is not visible on AppleTalk clients (e.g., G4 client):

1. **Verify service startup order:**
   ```bash
   # Check that jrouter started first
   sudo systemctl status jrouter
   
   # Check that atalkd started after jrouter
   sudo systemctl status atalkd
   
   # Verify dependencies
   systemctl show atalkd.service -p After -p Requires
   ```
   Should show: `After=... jrouter.service` and `Requires=jrouter.service`

2. **Verify NBP registration:**
   ```bash
   sudo nbplkup "macpro2013:AFPServer"
   ```
   Should show: `macpro2013:AFPServer  650.37:128`

3. **Restart services in correct order:**
   ```bash
   # Restart in dependency order
   sudo systemctl restart jrouter
   sudo systemctl restart atalkd
   sudo systemctl restart netatalk
   ```

4. **Check service status:**
   ```bash
   sudo systemctl status jrouter
   sudo systemctl status atalkd
   sudo systemctl status netatalk
   ```

5. **Verify atalkd configuration:**
   ```bash
   # Check that atalkd.conf has correct network and zone
   cat /home/blake/code/machine-cfg/macpro2013/atalkd.conf
   ```
   Should show: `enp12s0 -phase 2 -net 650 -addr 650.37 -zone "netjibbing"`
   **Important:** Network must be explicitly set to `650` (not `0-65534` for auto-detect)

6. **Verify interface configuration:**
   - Ensure `enp12s0` is up and has an IP address
   - Check that atalkd is using the correct interface

7. **Check zone visibility:**
   ```bash
   sudo getzones
   ```
   Should include "netjibbing" zone

8. **On the client:**
   - Try disabling and re-enabling AppleTalk
   - Wait a few seconds for NBP discovery to complete
   - Check that the client can see the zone list (from jrouter)

### Interface Separation with jrouter

**Important:** Netatalk and jrouter use separate network interfaces to avoid conflicts:
- **netatalk/atalkd:** `enp12s0` (192.168.0.214) - Regular AppleTalk node
- **jrouter:** `enp11s0` (192.168.0.212) - Seed router with promiscuous mode

Both interfaces are on the same broadcast domain, but each service has its own dedicated interface. This prevents packet capture conflicts and ensures proper operation of both services.

## Notes

- Build completed with one compiler warning in `lantest_io_monitor.c` (buffer truncation warning - non-critical)
- AppleTalk kernel modules loaded and configured
- Config file permissions set to 644 for proper access
- All configuration files located in `/home/blake/code/machine-cfg/macpro2013/`
- **Updated January 5, 2026:** AppleTalk re-configured after new build installation
  - Using jrouter as seed router (650.1) for network 650
  - atalkd configured with static network and address: `enp12s0 -phase 2 -net 650 -addr 650.37 -zone "netjibbing"`
  - Current address: 650.37 (static, separate from jrouter's 650.1)
  - **Interface Separation:** netatalk on enp12s0, jrouter on enp11s0 (with promiscuous mode)
  - **CNID Backend:** Rebuilt with SQLite as default CNID backend (replacing MySQL)
    - Build command: `meson setup build -Dbuildtype=release -Dwith-appletalk=true -Dwith-cups-pap-backend=true -Dwith-dbus-sysconf-path=/usr/share/dbus-1/system.d -Dwith-init-hooks=false -Dwith-tests=true -Dwith-testsuite=true -Dwith-cnid-default-backend=sqlite`
    - Install command: `sudo meson install -C build`
- **Updated January 5, 2026 (evening):** Verified working configuration
  - Both zone list (from jrouter) and Netatalk share visible on G4 client
  - Services restarted to refresh NBP registration after network changes
  - Interface separation confirmed working correctly
- **Updated January 20, 2026:** Improved startup process and configuration
  - Fixed atalkd.conf to use explicit `-net 650` instead of auto-detect `-net 0-65534`
  - Added explicit `-zone "netjibbing"` parameter to atalkd.conf
  - Updated atalkd.service to depend on jrouter.service (ensures seed router starts first)
  - Added startup order documentation and troubleshooting steps
  - **Root cause:** Auto-detection (`-net 0-65534`) can fail when atalkd starts before jrouter is fully ready, causing shares to not appear on AppleTalk network

## References

- Netatalk Documentation: https://netatalk.io/
- PR #2577: Issue #2524 Cache Validation Fixes
- Build instructions: `COMPILATION.md` in source repository

