# Netatalk "throwback" VM Configuration

This document describes the Netatalk AFP/AppleTalk configuration running on
the **throwback** development VM. This VM is used for long-term validation
testing of the custom Netatalk build (with AURP tunneling support).

---

## System Overview

| Item | Value |
|---|---|
| Hostname | throwback |
| OS | Ubuntu (VMware VM) |
| Netatalk version | 4.x (custom AURP build) |
| AppleTalk zone | netjibbing |
| AFP server name | throwback |
| Network interface | ens160 |

---

## Shares

Two AFP volumes are served:

### JonesFarm

| Setting | Value |
|---|---|
| Path | `/mnt/hgfs/MacPro` (VMware HGFS shared folder) |
| Guest access | Read-only (enforced by Unix permissions) |
| Authenticated access | Full read/write as user `blake` |
| Authentication | `uams_randnum.so` (Netatalk afppasswd, not Linux shadow) |

**Directory layout and permissions:**

| Directory | Mode | Guest access |
|---|---|---|
| `G4 Cube/` | `2755` (blake-owned, setgid) | Read-only |
| `Software/` | `2755` (blake-owned, setgid) | Read-only |
| `Drop Files Here/` | `0777` | Served separately via Drop Box share |

Guest (Classic Mac, no login) can browse and copy files from `G4 Cube` and
`Software`. Unix permissions (`unix priv = yes`) enforce the read-only
boundary at the AFP protocol layer, so no filesystem-level restrictions are
needed on the HGFS mount.

**Note on macOS AppleDouble sidecar files (`._*`):** Files placed directly in
the MacPro root by macOS may have `._filename` sidecar files. These are in
macOS AppleDouble format, which Netatalk does not read natively (it uses
`.AppleDouble/filename` format). Files with `._*` sidecars should be organized
into `G4 Cube/` or `Software/` subdirectories, or the `._*` files should be
removed from the Mac side, to avoid AFP error -39 (eofErr) during copies.
Subdirectories `G4 Cube/` and `Software/` do not have `._*` files and copy
correctly.

---

### Drop Box

| Setting | Value |
|---|---|
| Path | `/mnt/hgfs/MacPro/Drop Files Here` |
| Guest access | Read/write (no Unix privilege checking) |
| Authenticated access | Full read/write as user `blake` |
| Extended attributes | `ea = none` (no AppleDouble metadata) |

Guests can drop files without authentication. `ea = none` avoids the
`setfilparams` permission failure that occurs when AppleDouble metadata files
created through HGFS are owned by `blake` (UID 1001) and cannot be updated by
the `ubuntu` guest account (UID 1000).

---

## Authentication

Only two UAMs are loaded — legacy Classic Mac methods:

| UAM | Module | Description |
|---|---|---|
| Guest | `uams_guest.so` | No credentials required |
| 2-Way Randnum | `uams_randnum.so` | Classic Mac OS 7–9 password auth |

`uams_randnum.so` authenticates against Netatalk's own password file
(`/etc/netatalk/afppasswd`), **not** the Linux shadow/PAM stack.

To set or change blake's AFP password:
```bash
sudo afppasswd blake
```

To initialize the afppasswd file (already done):
```bash
sudo afppasswd -c
```

---

## HGFS Mount (`/mnt/hgfs`)

The MacPro share lives on the macOS host and is mounted into the VM via
VMware HGFS (vmhgfs-fuse).

**Key mount options:**

| Option | Purpose |
|---|---|
| `uid=1001,gid=1001` | Maps all HGFS file ownership to `blake` (UID 1001) |
| `allow_other` | Allows non-root users (ubuntu, afpd) to access the mount |
| *(no `default_permissions`)* | Allows macOS ACLs to govern access rather than Linux POSIX mode bits |

`default_permissions` is intentionally **omitted**. With it enabled, the Linux
kernel enforces POSIX mode bits only and ignores macOS ACLs, which blocks the
`ubuntu` guest account from writing to the `Drop Files Here/.AppleDouble`
directory. Without it, vmhgfs-fuse applies macOS ACL decisions, which allows
writes when the macOS-side ACL grants `everyone allow write`.

**macOS-side ACL required on `Drop Files Here`:**
```bash
# Run from macOS Terminal on the host:
chmod +a "everyone allow read,write,execute,file_inherit,directory_inherit" \
  "/Volumes/JonesFarm/MacPro/Drop Files Here"
chmod +a "everyone allow read,write,execute,file_inherit,directory_inherit" \
  "/Volumes/JonesFarm/MacPro/Drop Files Here/.AppleDouble"
```

**Systemd unit:** `/etc/systemd/system/mnt-hgfs.mount`

```ini
[Mount]
What=vmhgfs-fuse
Where=/mnt/hgfs
Type=fuse
Options=uid=1001,gid=1001,allow_other
```

---

## Service Startup Order

`netatalk.service` has two dependencies that ensure correct startup:

1. **`atalkd.service`** — must be running and have registered AppleTalk zones
   before AFP starts. A pre-start script polls `getzones` for up to 30 seconds
   to wait for atalkd to be ready.
2. **`mnt-hgfs.mount`** — HGFS must be mounted before Netatalk starts, since
   the AFP share paths live on the HGFS mount.

**Startup sequence on boot:**
```
mnt-hgfs.mount
    → atalkd.service  (registers NBP names: throwback:Workstation, throwback:netatalk)
        → netatalk.service (waits up to 30s for getzones, then starts AFP)
```

**`atalkd.service`** overrides the default hostname with a fixed AppleTalk
name via `systemctl set-environment ATALK_NAME=throwback` in `ExecStartPre`.

---

## Configuration Files

| File | Purpose |
|---|---|
| `/etc/netatalk/afp.conf` | AFP shares, UAMs, global options |
| `/etc/netatalk/afppasswd` | Netatalk user passwords (managed by `afppasswd`) |
| `/etc/systemd/system/netatalk.service` | AFP daemon (customized) |
| `/etc/systemd/system/atalkd.service` | AppleTalk daemon (customized) |
| `/etc/systemd/system/mnt-hgfs.mount` | VMware HGFS mount |
| `/etc/systemd/journald.conf.d/netatalk.conf` | Journal size cap (500 MB, 7-day retention) |

### `/etc/netatalk/afp.conf`

```ini
[Global]
server name = throwback
appletalk = yes
uam list = uams_randnum.so uams_guest.so
afp interfaces = ens160
ddp zone = netjibbing
guest account = ubuntu
log level = default:debug

[JonesFarm]
path = /mnt/hgfs/MacPro
cnid scheme = sqlite
guest ok = yes
read only = no
unix priv = yes
ea = ad
invisible dots = yes
veto files = /.DS_Store/.TemporaryItems/.Trashes/.fseventsd/

[Drop Box]
path = /mnt/hgfs/MacPro/Drop Files Here
cnid scheme = sqlite
guest ok = yes
read only = no
unix priv = no
ea = none
invisible dots = yes
veto files = /.DS_Store/.TemporaryItems/.Trashes/.fseventsd/
```

---

## Monitoring

A reliability monitor script runs every 30 minutes via systemd timer.

**Script:** `/usr/local/bin/netatalk_monitor.sh`  
**Log:** `/var/log/netatalk_monitor.log`  
**Units:** `netatalk-monitor.service` / `netatalk-monitor.timer`

The monitor checks:
- Service state and restart counts for `atalkd`, `netatalk`, `mnt-hgfs.mount`
- NBP registration of `throwback:AFPServer` in the `netjibbing` zone
- AURP zone count (warns if fewer than 5 zones visible)
- Disk space
- Critical log events (crash, segfault, abort) in the last 30 minutes
- AURP peer rejection counts

---

## Operational Notes

### Rebuilding Netatalk

Always use the `rebuild.sh` script in the repo root to build and install:
```bash
./rebuild.sh
```

After rebuilding, restart services:
```bash
sudo systemctl restart atalkd
sudo systemctl restart netatalk
```

### HGFS Mount Issues

If the HGFS mount drops (e.g. after host sleep/wake):
```bash
sudo systemctl restart mnt-hgfs.mount
sudo systemctl restart netatalk
```

### Checking Service Health

```bash
systemctl status atalkd netatalk mnt-hgfs.mount
journalctl -u netatalk -f
sudo /usr/local/bin/netatalk_monitor.sh   # run monitor on demand
cat /var/log/netatalk_monitor.log         # view monitor history
```

### Verifying NBP Registration

```bash
/usr/local/bin/nbplkup "=:AFPServer@netjibbing"
/usr/local/bin/getzones
```
