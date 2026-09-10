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

# AUX sample decoding supports raw TRBE trace. Select a usable CPU and name
# its sink explicitly to avoid a shared sink.
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
	# rm -rf "$tmpdir"
	echo "aaa"
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

# Record only the workload. Do not request hardware branch stacks or
# callchains: any history added below must come from the embedded AUX trace.
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
	local branches=$2
	local callchain=$3
	local output="$tmpdir/script-$options"

	perf script -i "$tmpdir/data" --itrace="$options" \
		-F comm,pid,tid,cpu,event,ip,sym,brstack >"$output" \
		2>"$tmpdir/stderr" || fail "Failed to decode AUX samples with $options"

	# Some windows may contain no complete trace. Require useful history in
	# multiple cycle samples, and check the depth limit for every sample.
	if ! awk -v max_branches="$branches" -v want_chain="$callchain" '
		function end_sample() {
			if (nr_branches)
				found_branches++
			if (workload_frames >= 2)
				found_chain++
			if (nr_branches > max_branches || nr_frames > 16)
				bad_depth = 1
			nr_branches = nr_frames = workload_frames = 0
		}
		# The event name may include a PMU prefix and configuration terms.
		$4 ~ /(^|\/)cycles([,\/:]|$)/ {
			end_sample()
			in_sample = 1
		}
		!NF {
			end_sample()
			in_sample = 0
		}
		in_sample {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^0x[[:xdigit:]]+\/0x[[:xdigit:]]+\//)
					nr_branches++
			if ($1 ~ /^[[:xdigit:]]+$/) {
				nr_frames++
				if ($2 ~ /^brstack(_|$)/)
					workload_frames++
			}
		}
		END {
			end_sample()
			exit bad_depth || (max_branches && found_branches < 2) ||
				(want_chain && found_chain < 2)
		}
	' "$output"; then
		head -n 80 "$output" >&2
		fail "Missing AUX sample history or incorrect depth with $options"
	fi
}

check_history L4 4 0
check_history L64 64 0
check_history G16 0 1
check_history G16L64 64 1

# Hiding history must leave exactly the original PMU samples, including
# their PID/TID, CPU and sampled IP, with no synthesized events. Per-thread
# recording does not require sample timestamps.
fields=comm,pid,tid,cpu,event,ip
perf script -i "$tmpdir/data" --no-itrace -F "$fields" \
	>"$tmpdir/original" 2>"$tmpdir/stderr" || fail "Failed to read cycle samples"
perf script -i "$tmpdir/data" --itrace=L4 -F "$fields" \
	>"$tmpdir/decoded" 2>"$tmpdir/stderr" || fail "Failed to decode cycle samples"
diff -u "$tmpdir/original" "$tmpdir/decoded" ||
	fail "AUX decoding changed the original cycle samples"

echo "CoreSight AUX sample decoding: PASS"
