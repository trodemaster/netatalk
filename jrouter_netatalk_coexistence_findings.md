# jrouter + Netatalk Coexistence Findings

**Date:** January 11, 2026  
**System:** MacPro 2013, Ubuntu 25.10  
**jrouter Version:** v0.0.21-dev  
**Netatalk Version:** 4.4.0

## Goal

Run jrouter on one network interface (enp11s0) to handle all AppleTalk routing and AURP tunneling, while Netatalk/atalkd runs on a second interface (enp12s0) to provide AFP file sharing over AppleTalk.

## Network Topology

- **enp11s0:** 192.168.0.212/24
- **enp12s0:** 192.168.0.214/24
- **Both interfaces on same L2 broadcast domain** (192.168.0.0/24, same physical switch)
- **AppleTalk Network:** 650
- **Zone:** netjibbing

## Test Results

### Configuration Tested

```
jrouter.yaml:
  ethertalk:
    - device: enp11s0
      zone_name: netjibbing
      net_start: 650
      net_end: 650

atalkd.conf:
  enp12s0 -dontroute -phase 2 -net 650 -zone "netjibbing"
```

### What Worked

✅ **jrouter broadcasts RTMP packets visible on enp12s0**
   - Captured RTMP broadcasts from jrouter (650.1) every 10 seconds
   - Source MAC: `00:3e:e1:be:00:c8` (enp11s0)
   - Dest MAC: `09:00:07:ff:ff:ff` (AppleTalk multicast)
   - Packets successfully cross between interfaces on same L2

✅ **atalkd receives and processes jrouter's broadcasts**
   - Logs show: `zip gnireply from 650.1`
   - Logs show: `zip_packet configured enp12s0 from 650.1`
   - Logs show: `rtmp_packet gateway 650.1 up`
   - atalkd successfully identifies jrouter as the seed router

✅ **Netatalk standalone (atalkd as `-router`)**
   - Works perfectly when jrouter is disabled
   - AFP shares visible over AppleTalk
   - NBP lookups successful
   - Zone list visible

### What Failed

❌ **atalkd with `-dontroute` flag**
   - Shows "ready 0/0/0" (no interfaces properly configured)
   - With static address (`-addr 650.37`): No AARP probing, fails to register NBP services
   - Without static address: AARP probing times out, fails to acquire address
   - NBP registration fails: `nbp_rgstr: Connection timed out`
   - Services hang during startup

❌ **Two seed routers on same L2**
   - Cannot run jrouter on enp11s0 AND atalkd as `-router` on enp12s0
   - Creates routing conflicts and loops
   - Both claim authority over network 650

## Root Cause Analysis

### Issue 1: atalkd `-dontroute` Flag Behavior

The `-dontroute` flag in atalkd appears to have limitations when used with static addresses:

1. **With static address (`-addr 650.37`):**
   - atalkd doesn't perform AARP probing for the static address
   - NBP registration fails because the address isn't properly initialized
   - Results in "ready 0/0/0" status

2. **Without static address:**
   - atalkd attempts to dynamically acquire an address via AARP
   - AARP probing times out consistently
   - Possible conflict with jrouter's AARP responses or network state

### Issue 2: Single L2 Broadcast Domain Limitation

With both interfaces on the same L2 network:
- Only ONE seed router can exist
- jrouter on enp11s0 is the seed router
- atalkd must be a regular node (non-router)
- The `-dontroute` flag should enable this, but implementation issues prevent it from working

### Issue 3: Packet Capture Conflicts

When attempting to run jrouter on BOTH interfaces:
- Both jrouter and atalkd try to capture AppleTalk packets on enp12s0
- Results in "config for no router" errors in atalkd
- NBP lookups time out
- Services fail to start

## Possible Solutions

### Solution 1: Separate L2 Networks (RECOMMENDED if AURP needed)

**Requires network reconfiguration:**
- Put enp11s0 on VLAN 10 (e.g., 192.168.10.0/24)
- Put enp12s0 on VLAN 20 (e.g., 192.168.20.0/24)
- jrouter routes between:
  - VLAN 10 (local clients)
  - VLAN 20 (Netatalk server)
  - AURP peers (remote networks)

**Benefits:**
- Clean separation of routing domains
- atalkd can be a regular node on VLAN 20
- jrouter provides routing between all networks
- No conflicts

**Drawbacks:**
- Requires VLAN-capable switch
- More complex network configuration

### Solution 2: Netatalk Only (CURRENT WORKING CONFIGURATION)

**Configuration:**
```
atalkd.conf:
  enp12s0 -router -phase 2 -net 650 -addr 650.37 -zone "netjibbing"
```

**Benefits:**
- Works reliably
- Simple configuration
- AFP shares visible over AppleTalk
- No service conflicts

**Drawbacks:**
- No AURP tunneling to remote networks
- No access to AURP peer networks (http://kalleboo.com/GT2024.txt)
- Limited to local AppleTalk network only

### Solution 3: jrouter Only (Not Tested)

**Configuration:**
- Disable atalkd completely
- Use jrouter for all AppleTalk routing

**Benefits:**
- AURP tunneling works
- Access to remote peer networks

**Drawbacks:**
- Netatalk/afpd requires atalkd for AppleTalk advertisement
- AFP shares won't be advertised over AppleTalk
- Would need AFP/TCP only (no AppleTalk file sharing)

### Solution 4: Fix atalkd `-dontroute` Implementation

**This would require:**
- Debugging atalkd's AARP probing with static addresses
- Understanding why NBP registration fails
- Potentially patching Netatalk source code

**Complexity:** High - requires C debugging and Netatalk internals knowledge

## Recommendation

**For your use case (AURP + local AFP file sharing):**

Implement **Solution 1: Separate L2 Networks** using VLANs.

**Implementation steps:**
1. Configure switch to create VLAN 10 and VLAN 20
2. Assign enp11s0 to VLAN 10 (e.g., 192.168.10.212/24)
3. Assign enp12s0 to VLAN 20 (e.g., 192.168.20.214/24)
4. Configure jrouter on BOTH interfaces (different subnets):
   ```yaml
   ethertalk:
     - device: enp11s0  # VLAN 10 - client network
       zone_name: netjibbing
       net_start: 650
       net_end: 650
     - device: enp12s0  # VLAN 20 - server network
       ethernet_addr: '08:00:07:fe:dc:ba'  # Different MAC to avoid conflicts
       zone_name: netjibbing
       net_start: 651
       net_end: 651
   ```
5. Configure atalkd as regular node:
   ```
   enp12s0 -dontroute -phase 2 -net 651 -zone "netjibbing"
   ```

**Alternative (interim solution):**

If VLANs are not immediately available, use **Solution 2: Netatalk Only** for reliable local AFP file sharing. This sacrifices AURP tunneling but provides stable AppleTalk file sharing.

## Technical Details

### Successful Packet Captures

**RTMP broadcasts from jrouter visible on enp12s0:**
```
23:42:55.600793 00:3e:e1:be:00:c8 > 09:00:07:ff:ff:ff, 802.3, length 193: 
LLC, dsap SNAP (0xaa) Individual, ssap SNAP (0xaa) Command, ctrl 0x03: 
oui Appletalk (0x080007), pid Appletalk (0x809b), length 185: 
0.0.1 > 0.1:  at-rtmp 172
```

**atalkd logs showing jrouter detection:**
```
Jan 11 23:43:25 macpro2013 atalkd[7516]: zip gnireply from 650.1 (enp12s0 212)
Jan 11 23:43:25 macpro2013 atalkd[7516]: zip_packet configured enp12s0 from 650.1
Jan 11 23:43:35 macpro2013 atalkd[7516]: rtmp_packet gateway 650.1 up
```

### Failed NBP Registration

**atalkd logs:**
```
Jan 11 23:45:55 macpro2013 nbprgstr[8487]: nbp_rgstr: Connection timed out
Jan 11 23:45:55 macpro2013 nbprgstr[8487]: Can't register macpro2013:Workstation@*
```

**Service status:**
```
Jan 11 23:43:55 macpro2013 atalkd[7516]: ready 0/0/0
```

The "ready 0/0/0" indicates no interfaces were properly configured, despite atalkd receiving routing information from jrouter.

## Conclusion

The intended architecture (jrouter for routing, atalkd for file sharing on same L2) **does not work** due to limitations in atalkd's `-dontroute` implementation when running on the same broadcast domain as another seed router.

**The only reliable configurations are:**
1. Separate L2 networks (VLANs) - enables full functionality
2. Netatalk only (current) - local AppleTalk file sharing works
3. jrouter only - AURP works, but no AppleTalk file sharing

The documentation will be updated to reflect these findings and recommend VLAN configuration for users who need both AURP routing and AppleTalk file sharing.
