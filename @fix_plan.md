# Ralph Fix Plan - Netatalk AURP Implementation

## High Priority

- [x] Review the requirements AURP_IMPLEMENTATION_PLAN.md and specs/requirements.md
- [x] Create AURP foundation files (aurp.h, aurp.c, aurp_peer.c, aurp_config.c)
- [x] Integrate AURP into main.c select() loop and timer
- [x] Integrate AURP configuration parsing into config.c
- [x] Test compilation and fix build errors
- [ ] Confirm basic AURP initialization and socket creation (runtime test with config file)

## Medium Priority

- [ ] Implement routing table integration (Phase 4 - aurp_rtmp.c)
- [ ] Implement RI-Rsp packet building with routing tuples
- [ ] Implement RI-Rsp parsing and route installation
- [ ] Implement RI-Upd for incremental route updates
- [ ] Test route learning from AURP peers with jrouter

## Low Priority

- [ ] Implement zone information exchange (Phase 5 - aurp_zip.c)
- [ ] Implement ZI-Req/ZI-Rsp packet handling
- [ ] Implement DDP packet encapsulation for data forwarding (Phase 6)
- [ ] Add comprehensive error recovery mechanisms
- [ ] Performance optimization and stress testing

## Completed

- [x] Project initialization
- [x] Created aurp.h with all AURP structures, constants, and RFC 1504 definitions
- [x] Created aurp.c with UDP socket handling and packet encoding/decoding
- [x] Created aurp_peer.c with peer state machine and connection management
- [x] Created aurp_config.c for configuration parsing
- [x] Updated meson.build to include AURP source files
- [x] Documented implementation status in @AGENT.md

## Implementation Notes

### Current Phase: Phase 2 - Integration (COMPLETED)

**Completed in Phase 1:**
1. AURP header file with complete RFC 1504 structures
2. UDP socket creation and binding
3. Packet encoding/decoding (domain identifiers, headers)
4. Peer lifecycle management (create, find, free)
5. Connection state machines (Open-Req/Rsp, Tickle/Ack)
6. Timer processing for retransmits and keepalives
7. Configuration parsing for aurp-peer, aurp-port, aurp-listen, aurp-open-peering

**Completed in Phase 2:**
1. Modified main.c to add AURP socket to main select() loop
2. Added aurp_init() call during daemon startup
3. Added aurp_input() call when AURP socket is readable
4. Added aurp_timer() call from existing as_timer() function
5. Added aurp_shutdown() call during daemon cleanup
6. Modified config.c readconf() to detect and parse AURP directives
7. Compilation test passed - atalkd builds with AURP support

**Next Steps (Phase 3 - Testing):**
1. Create sample atalkd.conf with AURP configuration
2. Run atalkd with AURP enabled and verify socket creation
3. Test AURP peer connection establishment with jrouter or another AURP peer

### Key Technical Decisions

1. **AURP as separate UDP socket**: Unlike RTMP/ZIP/NBP which use AF_APPLETALK sockets, AURP uses a separate UDP/IP socket for tunneling
2. **Stub functions for later phases**: RI-Rsp building, route management, and zone exchange are stubbed to allow incremental development
3. **Modular configuration**: Created aurp_config.c separately to minimize changes to existing config.c
4. **State machine design**: Separate sender and receiver states per RFC 1504 specification

### Testing Strategy

**Phase 2 Testing:**
- Verify compilation succeeds
- Test AURP socket creation and binding
- Test configuration parsing with sample atalkd.conf
- Verify daemon starts with AURP enabled
- Check log output for AURP initialization

**Phase 4 Testing (Route Exchange):**
- Test with jrouter as peer
- Verify route learning from AURP peers
- Test route propagation to local interfaces
- Verify routing loop prevention

**Phase 5-6 Testing:**
- Zone information exchange
- End-to-end DDP packet forwarding
- Multi-peer scenarios

## Architecture Overview

```
atalkd (main daemon)
├── Existing Protocols
│   ├── RTMP (port 1) - Local routing via AppleTalk
│   ├── NBP (port 2) - Name binding
│   ├── AEP (port 4) - Echo protocol
│   └── ZIP (port 6) - Zone information
└── AURP (NEW) - IP tunneling
    ├── aurp.c - UDP socket, packet encoding/decoding
    ├── aurp_peer.c - Peer state machines, timers
    ├── aurp_config.c - Configuration parsing
    ├── aurp_rtmp.c - Route table integration (Phase 4)
    └── aurp_zip.c - Zone integration (Phase 5)
```

## Reference Files

- `specs/requirements.md` - Full AURP implementation plan
- `jrouter_netatalk_coexistence_findings.md` - Testing results
- `netatalk_setup.md` - Netatalk host setup
- `/Users/blake/code/jrouter` - Go AURP reference implementation

## Development Guidelines

- **Code Style**: Match existing netatalk C style (BSD-style)
- **Logging**: Use LOG() macro with log_info, log_error, log_debug, log_warning
- **Error Handling**: Check all malloc/socket/IO operations, clean up on errors
- **Testing**: Build and test after each major change
- **Documentation**: Update @AGENT.md and this file with progress

## Focus Areas

1. **Correctness**: RFC 1504 compliance is critical
2. **Stability**: Robust error handling and recovery
3. **Integration**: Clean integration with existing atalkd code
4. **Testability**: Log enough information for debugging
5. **Maintainability**: Clear code structure, good comments

## Known Challenges

1. Integration with config.c requires minimal changes to readconf()
2. Integration with main.c requires understanding select() loop
3. Route table integration requires understanding rtmp.c structures
4. Zone integration requires understanding zip.c zone management
5. Testing requires multiple hosts or VMs with AppleTalk support

---

**Last Updated**: 2026-01-12 (Ralph Loop #2)
**Current Status**: Phase 1 and Phase 2 complete
**Next Priority**: Runtime testing with AURP configuration, then Phase 4 (Route Exchange)
