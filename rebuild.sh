#!/usr/bin/env bash
set -euo pipefail

sudo systemctl stop atalkd netatalk

meson compile -C /home/blake/code/netatalk/build
sudo meson install -C /home/blake/code/netatalk/build

sudo systemctl start netatalk atalkd
