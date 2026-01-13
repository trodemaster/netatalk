# AURP Integration Patches for main.c and config.c

## Patch 1: main.c - Add AURP Header Include

**Location**: After line 56 (`#include "main.h"`)

**Add**:
```c
#include "aurp.h"
```

## Patch 2: main.c - Initialize AURP After Configuration

**Location**: After line 1172 (`bootaddr(ciface);`)

**Add**:
```c
    /* Initialize AURP if enabled */
    if (aurp_config.ac_enabled) {
        if (aurp_init(&aurp_config) < 0) {
            LOG(log_error, logtype_atalkd, "AURP initialization failed");
            /* Continue without AURP - not fatal */
        }
    }
```

## Patch 3: main.c - Add AURP Socket to Select Loop

**Location**: In setaddr() function, after line 1465 (`}`)
This is right after the loop that adds interface ports to fds.

**Add**:
```c

    /* Add AURP socket to select set */
    if (aurp_fd >= 0) {
        FD_SET(aurp_fd, &fds);
        if (aurp_fd > nfds) {
            nfds = aurp_fd;
        }
    }
```

## Patch 4: main.c - Handle AURP Socket in Main Loop

**Location**: In main() function, after the interface/port loop ends (after line ~1270)
Look for the closing braces of the nested loops that handle interface ports.

**Add** (after the interface loop closes, before the `}` of the select handling):
```c

        /* Handle AURP socket */
        if (aurp_fd >= 0 && FD_ISSET(aurp_fd, &readfds)) {
            aurp_input(aurp_fd);
        }
```

## Patch 5: main.c - Call AURP Timer

**Location**: In as_timer() function, at the end (before the closing brace around line 855)

**Add**:
```c

    /* Call AURP timer */
    if (aurp_fd >= 0) {
        aurp_timer();
    }
```

## Patch 6: main.c - Shutdown AURP

**Location**: In as_down() function, before the LOG("done") line (before line 888)

**Add**:
```c

    /* Shutdown AURP */
    if (aurp_fd >= 0) {
        aurp_shutdown();
    }
```

## Patch 7: config.c - Add AURP Header Include

**Location**: After line 42 (`#include "main.h"`)

**Add**:
```c
#include "aurp.h"
```

## Patch 8: config.c - Handle AURP Configuration Lines

**Location**: In readconf() function, after line 361 (after `at_parseline()` call)
We need to check if the line is an AURP directive before treating it as an interface.

**Replace** this section (lines 362-401):
```c
#ifndef __svr4__
        /*
         * Check that av[ 0 ] is a valid interface.
         * Not possible under sysV.
         */
        strlcpy(ifr.ifr_name, argv[0], sizeof(ifr.ifr_name));
```

**With**:
```c
        /* Check if this is an AURP configuration line */
        if (strncmp(argv[0], "aurp-", 5) == 0) {
            if (aurp_config_parse(argv) < 0) {
                fprintf(stderr, "AURP configuration error: %s\n", argv[0]);
                goto read_conf_err;
            }
            freeline(argv);
            continue;
        }

#ifndef __svr4__
        /*
         * Check that av[ 0 ] is a valid interface.
         * Not possible under sysV.
         */
        strlcpy(ifr.ifr_name, argv[0], sizeof(ifr.ifr_name));
```

## Summary of Changes

### main.c Changes:
1. Include aurp.h header
2. Initialize AURP after bootaddr() call
3. Add AURP socket to FD_SET in setaddr()
4. Handle AURP socket events in main select() loop
5. Call aurp_timer() from as_timer()
6. Call aurp_shutdown() from as_down()

### config.c Changes:
1. Include aurp.h header
2. Check for aurp- prefix before processing interface lines
3. Call aurp_config_parse() for AURP directives

## Testing After Integration

```bash
# Compile
meson compile -C build

# Check for compilation errors
# If successful, test with minimal config:
echo "aurp-listen 0.0.0.0" | sudo tee /etc/atalkd.conf
echo "aurp-port 387" | sudo tee -a /etc/atalkd.conf
echo "lo0" | sudo tee -a /etc/atalkd.conf

# Run atalkd in debug mode
sudo ./build/etc/atalkd/atalkd -d
```
