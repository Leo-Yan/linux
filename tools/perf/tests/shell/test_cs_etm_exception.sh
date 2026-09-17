#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# CoreSight exception branch samples without trace hardware

perf check feature -q libopencsd || exit 2
command -v python3 >/dev/null 2>&1 || exit 2

exec python3 "$(dirname "$0")/lib/cs_etm_exception.py"
