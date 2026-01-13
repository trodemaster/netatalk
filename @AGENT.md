# Agent Build Instructions - Netatalk AURP Implementation

## Project Overview

This is the netatalk AppleTalk protocol suite, with AURP (AppleTalk Update-Based Routing Protocol) IP tunneling being implemented in the atalkd daemon.

## Project Setup

### Prerequisites
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential meson ninja-build libavahi-client-dev \
    libacl1-dev libdb-dev libevent-dev libgcrypt20-dev libkrb5-dev \
    libldap2-dev libpam0g-dev libssl-dev libtirpc-dev

# Or for other systems, check INSTALL.md in the project root
```

### Building the Project
```bash
# From project root (/Users/blake/Developer/netatalk)

# Setup build directory
meson setup build

# Compile
meson compile -C build

# Install (optional, requires sudo)
sudo meson install -C build
```

## Running Tests
```bash
# Build tests (if available)
meson test -C build

# Specific atalkd testing
# (Will be added as AURP implementation progresses)
```

## AURP Implementation Status

### Phase 1: Foundation (COMPLETED)
- [x] Created `etc/atalkd/aurp.h` - AURP structures, constants, and prototypes
- [x] Created `etc/atalkd/aurp.c` - UDP socket handling and packet encoding/decoding
- [x] Created `etc/atalkd/aurp_peer.c` - Peer state machine and route management
- [x] Created `etc/atalkd/aurp_config.c` - Configuration parsing
- [x] Updated `etc/atalkd/meson.build` - Added AURP source files to build

### Phase 2: Integration (COMPLETED)
- [x] Integrate AURP into main.c select() loop
- [x] Add AURP configuration parsing integration to config.c readconf()
- [x] Test compilation and fix any build errors
- [x] Initialize AURP on daemon startup

### Phase 3: Testing (COMPLETED)
- [x] Basic UDP packet send/receive testing
- [x] AURP socket binding and listening confirmed
- [x] Configuration parsing (aurp-listen, aurp-open-peering) working
- [x] Log messages verified: "AURP initialized", "AURP enabled"
- [x] atalkd service running with AURP on 192.168.0.214:387

### Phase 4: Route Exchange (COMPLETED)
- [x] Implement RI-Rsp packet building with routing tuples
- [x] Implement RI-Rsp packet parsing and route installation
- [x] Implement RI-Upd for incremental updates (event tuple parsing)
- [x] Implement route management (add/remove/update routes)
- [x] Added RTMPTAB_AURP flag for AURP-learned routes
- [x] AURP service running and ready for peer connections

### Phase 5: Zone Information (COMPLETED)
- [x] Implement ZI-Req/ZI-Rsp packet handling
- [x] Integrate with zip.c zone management (addzone())
- [x] Request zones after RI-Rsp using SZI flag
- [x] Parse zone tuples and add to AURP-learned routes

### Phase 6: Data Forwarding (PENDING - Per requirements.md)
- [ ] Implement DDP packet encapsulation
- [ ] Route encapsulated packets to local interfaces
- [ ] Test end-to-end AppleTalk connectivity

## Configuration Format

AURP configuration is added to `/etc/atalkd.conf` (or configured location):

```conf
# Existing interface configuration (unchanged)
eth0 -seed -phase 2 -net 100-100 -addr 100.1 -zone "My Zone"

# AURP global configuration (new)
aurp-listen 0.0.0.0          # IP address to bind UDP socket (default: 0.0.0.0)
aurp-port 387                 # UDP port number (default: 387)
aurp-open-peering no          # Accept connections from unknown peers (default: no)

# AURP peers (can specify multiple)
aurp-peer 192.168.1.100       # By IP address
aurp-peer router.example.com  # By hostname
aurp-peer 10.0.0.1            # Another peer
```

## Key Implementation Files

### Core AURP Files (New)
- `etc/atalkd/aurp.h` - Header with structures and constants (RFC 1504 compliant)
- `etc/atalkd/aurp.c` - UDP socket, packet encoding/decoding (~600 lines)
- `etc/atalkd/aurp_peer.c` - Peer state machine (~700 lines)
- `etc/atalkd/aurp_config.c` - Configuration parsing (~180 lines)

### Integration Points (To Be Modified)
- `etc/atalkd/main.c` - Add AURP to main select() loop and timer
- `etc/atalkd/config.c` - Integrate AURP config parsing
- `etc/atalkd/rtmp.c` - Route table integration (Phase 4)
- `etc/atalkd/zip.c` - Zone information integration (Phase 5)

## Known Build Issues

None - AURP integration compiles successfully (tested 2026-01-12).

## Development Workflow

1. Make code changes
2. Recompile: `meson compile -C build`
3. Test functionality
4. Commit working changes with descriptive messages
5. Update @fix_plan.md with progress

## Key Learnings

### AURP Protocol Notes
- Sequence numbers: Must never be 0, use 1-65535
- Connection IDs: Must never be 0, randomly generated
- Timer intervals: Tickle every 10s, timeout after 90s
- Retry limits: 5 retries for sends, 10 for tickles
- Domain identifiers: NULL (0x00) or IP (0x01, 4 bytes)

### Netatalk atalkd Architecture
- Main loop: `select()` based with `fd_set`
- Timer: 10-second SIGALRM handler (`as_timer()`)
- Protocols: RTMP (port 1), NBP (port 2), AEP (port 4), ZIP (port 6)
- AURP will use separate UDP socket (not AppleTalk socket)

### Integration Pattern
- AURP socket added to main select() fd_set
- `aurp_input()` called when socket readable
- `aurp_timer()` called from main timer handler
- `aurp_shutdown()` called on daemon exit

## Reference Documentation

- RFC 1504: AppleTalk Update-Based Routing Protocol
- specs/requirements.md: Full implementation plan
- jrouter source: /Users/blake/code/jrouter (Go reference implementation)
- Inside AppleTalk, Second Edition (Apple Computer)

## Testing Strategy

### Unit Testing
- Packet encoding/decoding correctness
- Sequence number arithmetic
- Domain identifier parsing

### Integration Testing
- UDP socket communication
- Peer connection establishment
- Route propagation
- Zone information exchange
- Reconnection after failures

### System Testing
- Multi-peer scenarios
- Mixed seed/non-seed configurations
- Network failure recovery
- Performance under load

## Next Steps

1. ~~Complete main.c integration (add AURP socket to select loop)~~ DONE
2. ~~Complete config.c integration (parse AURP directives)~~ DONE
3. ~~Run first compilation test~~ DONE - Compiles successfully
4. ~~Fix any compilation errors~~ DONE - No errors
5. ~~Test basic AURP initialization with sample config file~~ DONE - Working on 192.168.0.214:387
6. ~~Phase 4 (Route Exchange) implementation~~ DONE
7. ~~Phase 5 (Zone Information) implementation~~ DONE
   - ~~Implement ZI-Req/ZI-Rsp packet handling~~
   - ~~Integrate with zip.c zone management~~
8. Test AURP peer connections when peers become available
9. Move to Phase 6 (Data Forwarding) implementation
   - Implement DDP packet encapsulation (AURP packet type 0x0002)
   - Route encapsulated packets to local interfaces

## Commit Guidelines

Use conventional commit format:
- `feat(aurp):` - New AURP features
- `fix(aurp):` - Bug fixes in AURP code
- `test(aurp):` - AURP testing additions
- `docs(aurp):` - AURP documentation updates
- `refactor(aurp):` - AURP code refactoring

Example: `feat(aurp): implement Open-Req/Open-Rsp handshake`

## Ralph Integration Notes

- This implementation is designed to work with Ralph autonomous agent
- Each phase is a manageable unit of work
- Stub functions allow incremental implementation
- Extensive logging for debugging and monitoring
- Clear separation of concerns for maintainability
