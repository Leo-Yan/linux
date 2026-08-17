#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0
# CoreSight branch history on existing samples (exclusive)

perf list pmu | grep -q 'cs_etm//' || exit 2

if [ "$(id -u)" != 0 ]; then
	echo "[Skip] No root permission"
	exit 2
fi

tmpdir=$(mktemp -d /tmp/perf-cs-add-last-branch.XXXXX)

cleanup()
{
	rm -rf "$tmpdir"
	trap - EXIT TERM INT
}

# shellcheck disable=SC2317 # Called through trap.
trap_cleanup()
{
	cleanup
	exit 1
}
trap trap_cleanup EXIT TERM INT

record_data()
{
	local cf="$tmpdir/ctl"
	local af="$tmpdir/ack"

	mkfifo "$cf" "$af"

	# Pin to one CPU so proc1 and proc2 alternate in one per-CPU trace
	# buffer. Start disabled and use the control FIFO to record only the
	# workload, not perf test setup and teardown.
	if perf record -T -o "$tmpdir/data" -C 0 -D -1 \
		--control fifo:"$cf","$af" \
		-e cs_etm/aux-action=start-paused/u \
		-e cycles/aux-action=resume,period=550019/u \
		-e cycles/aux-action=pause,period=100003,call-graph=fp/u -- \
		taskset --cpu-list 0 perf test --record-ctl fifo:"$cf","$af" \
		-w context_switch_loop 10000 \
		>/dev/null 2>"$tmpdir/stderr"; then
		return 0
	fi

	echo "Failed to record ETM trace with AUX pause/resume" >&2
	cat "$tmpdir/stderr" >&2
	return 1
}

decode()
{
	local size=$1
	local output=$2

	if perf script -i "$tmpdir/data" --itrace="L$size" \
		-F comm,pid,tid,event,ip,brstack >"$output" \
		2>"$tmpdir/stderr"; then
		return 0
	fi

	if grep -q "itrace=L requires virtual timestamped trace" \
		"$tmpdir/stderr"; then
		echo "[Skip] Virtual CoreSight timestamps are not available"
		cleanup
		exit 2
	fi

	cat "$tmpdir/stderr" >&2
	return 1
}

check_process_samples()
{
	local output=$1
	local comm

	# Expect each process to have a pause-event sample followed by at least
	# one branch entry in 0xFROM/0xTO/... form.
	for comm in proc1 proc2; do
		awk -v comm="$comm" '
			$1 == comm && /cycles\/aux-action=pause/ {
				in_sample = 1
				next
			}
			!NF {
				in_sample = 0
				next
			}
			in_sample && /0x[[:xdigit:]]+\/0x[[:xdigit:]]+\// {
				found = 1
			}
			END { exit !found }
		' "$output" || {
			echo "No pause-event branch stack found for $comm" >&2
			grep -A 4 "^$comm .*cycles/aux-action=pause" "$output" \
				| head -n 20 >&2 || true
			return 1
		}
	done
}

check_callchains()
{
	local output="$tmpdir/script-callchain"
	local comm

	if ! perf script -i "$tmpdir/data" -F comm,event,ip >"$output" \
		2>"$tmpdir/stderr"; then
		echo "Failed to dump pause-event callchains" >&2
		cat "$tmpdir/stderr" >&2
		return 1
	fi

	# Expect a pause-event header for each process followed by at least two
	# indented instruction-pointer frames.
	for comm in proc1 proc2; do
		awk -v comm="$comm" '
			$1 == comm && /cycles\/aux-action=pause/ {
				in_sample = 1
				frames = 0
				next
			}
			!NF {
				if (in_sample && frames >= 2)
					found = 1
				in_sample = 0
				next
			}
			in_sample && /^[[:space:]]+[[:xdigit:]]+([[:space:]]|$)/ {
				frames++
			}
			END {
				if (in_sample && frames >= 2)
					found = 1
				exit !found
			}
		' "$output" || {
			echo "No multi-frame pause-event callchain found for $comm" >&2
			grep -A 8 "^$comm .*cycles/aux-action=pause" "$output" \
				| head -n 40 >&2 || true
			return 1
		}
	done
}

check_branch_stacks()
{
	local output=$1
	local max_entries=$2

	local ret

	if awk -v max="$max_entries" '
		/0x[[:xdigit:]]+\/0x[[:xdigit:]]+\// {
			entries = 0
			for (i = 1; i <= NF; i++)
				if ($i ~ /^0x[[:xdigit:]]+\/0x[[:xdigit:]]+\//)
					entries++
			if (entries)
				found = 1
			if (entries > max) {
				status = 2
				exit
			}
		}
		END {
			if (status)
				exit status
			if (!found)
				exit 1
		}
	' "$output"; then
		return 0
	else
		ret=$?
	fi

	case $ret in
	1) echo "No ETM branch stacks found" >&2 ;;
	2) echo "Branch stack exceeds requested L$max_entries depth" >&2 ;;
	esac
	# Expected decoded pause-event lines contain at most L<n> branch entries.
	grep 'cycles/aux-action=pause' "$output" | head -n 5 >&2 || true
	return 1
}

record_data
check_callchains

decode 4 "$tmpdir/script-L4"
check_process_samples "$tmpdir/script-L4"
check_branch_stacks "$tmpdir/script-L4" 4

decode 64 "$tmpdir/script-L64"
check_process_samples "$tmpdir/script-L64"
check_branch_stacks "$tmpdir/script-L64" 64

cleanup
exit 0
