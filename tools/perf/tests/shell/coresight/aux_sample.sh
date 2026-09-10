#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0
# CoreSight AUX samples with callchains and branch stacks (exclusive)

export LC_ALL=C

skip()
{
	echo "[Skip] $1"
	exit 2
}

perf list pmu | grep -q 'cs_etm//' || skip "cs_etm is not available"
perf check feature -q libopencsd || skip "perf was built without OpenCSD"
[ "$(id -u)" = 0 ] || skip "No root permission"
command -v taskset >/dev/null || skip "taskset is not available"

# AUX sample now supports per CPU sink (e.g., TRBE). Select a usable CPU
# and name its sink explicitly to avoid a shared sink.
sink=
for dev in /sys/bus/coresight/devices/trbe[0-9]*; do
	[ -d "$dev" ] || continue
	name=${dev##*/}
	cpu=${name#trbe}
	[ -e "/sys/bus/event_source/devices/cs_etm/cpu$cpu" ] || continue
	if taskset -c "$cpu" true 2>/dev/null; then
		sink=$name
		break
	fi
done
[ -n "$sink" ] || skip "No usable TRBE CPU is available"

tmpdir=$(mktemp -d /tmp/perf-cs-aux-sample.XXXXXX)

cleanup()
{
	rm -rf "$tmpdir"
}

trap cleanup EXIT
trap 'exit 1' TERM INT

fail()
{
	echo "$1" >&2
	cat "$tmpdir/stderr" >&2
	exit 1
}

cf="$tmpdir/ctl"
af="$tmpdir/ack"
mkfifo "$cf" "$af"

# Disable trace timestamps and context IDs to use the owning sample's context.
# Use a per-thread mmap so the explicit sink is only used on the pinned CPU.
if ! taskset -c "$cpu" perf record -o "$tmpdir/data" --aux-sample=8192 \
	-e "{cs_etm/@$sink,timestamp=0,contextid=0/u,cycles/period=100003/u}" \
	--per-thread -D -1 --control fifo:"$cf","$af" -- \
	perf test --record-ctl fifo:"$cf","$af" -w brstack 1000000 \
	>/dev/null 2>"$tmpdir/stderr"; then
	# Kernels without snapshot_aux reject the sampling event at open time.
	if grep -Eq 'sys_perf_event_open.*event \(.*cycles.*\): Invalid argument' \
		"$tmpdir/stderr"; then
		skip "Kernel does not accept CoreSight AUX sampling"
	fi
	fail "Failed to record CoreSight AUX samples"
fi

perf evlist -v -i "$tmpdir/data" >"$tmpdir/evlist" 2>"$tmpdir/stderr" ||
	fail "Failed to read AUX sample attributes"
grep -Eq 'sample_type:.*\|AUX(,|\|).*aux_sample_size: 8192(,|$)' \
	"$tmpdir/evlist" || fail "Missing AUX sample attributes"

check_history()
{
	local options=$1
	local max_branches=$2
	local max_callchains=$3
	local output="$tmpdir/script-$options"

	perf script -i "$tmpdir/data" --itrace="$options" \
		-F comm,pid,tid,cpu,event,ip,sym,brstack >"$output" \
		2>"$tmpdir/stderr" || fail "Failed to decode AUX samples with $options"

	# Some windows may contain incomplete trace. Require at least one cycle
	# sample to reach both requested depths, and reject any that exceed them.
	if ! awk -v max_branches="$max_branches" \
		-v max_callchains="$max_callchains" '
		function check_sample() {
			if (in_sample == 0) {
				return
			}

			if (branch_entries > max_branches || callchain_frames > max_callchains) {
				depth_exceeded = 1
			}

			# Both depths must be reached in the same sample, with all
			# callchain frames belonging to the brstack workload.
			if (branch_entries == max_branches &&
			    callchain_frames == max_callchains &&
			    workload_frames == max_callchains) {
				found_sample = 1
			}

			branch_entries = 0
			callchain_frames = 0
			workload_frames = 0
			in_sample = 0
		}
		{
			# A blank line marks the end of a sample.
			if (NF == 0) {
				check_sample()
				next
			}

			# Sample header: comm pid/tid [cpu] event ...
			# The event may include a PMU prefix and configuration terms.
			if ($4 ~ /(^|\/)cycles([,\/:]|$)/) {
				check_sample()
				in_sample = 1
			}
			if (in_sample == 0) {
				next
			}

			# Each branch entry is a field in 0xFROM/0xTO/... form.
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^0x[[:xdigit:]]+\/0x[[:xdigit:]]+\//) {
					branch_entries++
				}
			}

			# Callchain rows start with a hexadecimal IP, then a symbol.
			if ($1 ~ /^[[:xdigit:]]+$/) {
				callchain_frames++
				if ($2 ~ /^brstack(_|$)/) {
					workload_frames++
				}
			}
		}
		END {
			# Account for the last sample even without a trailing blank line.
			check_sample()

			if (depth_exceeded != 0) {
				print "AUX sample history exceeds the requested depth" > "/dev/stderr"
				exit 1
			}
			if (found_sample == 0) {
				printf "No sample has %d branches and %d workload callchain frames\n", \
					max_branches, max_callchains > "/dev/stderr"
				exit 1
			}
			exit 0
		}
	' "$output"; then
		head -n 80 "$output" >&2
		fail "Missing AUX sample history or incorrect depth with $options"
	fi
}

check_sample_identity()
{
	local fields=comm,pid,tid,cpu,event,ip

	# Hiding history must leave exactly the original PMU samples, including
	# their PID/TID, CPU and sampled IP, with no synthesized events. Per-thread
	# recording does not require sample timestamps.
	perf script -i "$tmpdir/data" --no-itrace -F "$fields" \
		>"$tmpdir/original" 2>"$tmpdir/stderr" || fail "Failed to read cycle samples"
	perf script -i "$tmpdir/data" --itrace=L4 -F "$fields" \
		>"$tmpdir/decoded" 2>"$tmpdir/stderr" || fail "Failed to decode cycle samples"
	diff -u "$tmpdir/original" "$tmpdir/decoded" ||
		fail "AUX decoding changed the original cycle samples"
}

check_history L4 4 0
check_history L64 64 0

# brstack -> brstack_bench -> brstack_foo -> brstack_bar provides three
# nested calls whose caller frames can be reconstructed from an AUX window.
check_history G3 0 3
check_history G3L64 64 3

check_sample_identity

echo "CoreSight AUX sample decoding: PASS"
