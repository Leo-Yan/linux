#!/bin/bash
# Check Arm CoreSight synthesized callchain (exclusive)
# SPDX-License-Identifier: GPL-2.0

glb_err=0

tmpdir=$(mktemp -d /tmp/perf-cs-callchain-test.XXXXXX)

cleanup_files()
{
	rm -rf "$tmpdir"
}

trap cleanup_files EXIT
trap 'cleanup_files; exit $glb_err' TERM INT

skip_if_system_is_not_ready()
{
	[ "$(uname -m)" = "aarch64" ] || {
		echo "Skip: arm64 only test" >&2
		return 2
	}

	perf list | grep -q 'cs_etm//' || {
		echo "Skip: cs_etm event is not available" >&2
		return 2
	}

	command -v gcc >/dev/null 2>&1 || {
		echo "Skip: gcc is not available" >&2
		return 2
	}

	return 0
}

build_test_program()
{
	local src=$1
	local bin=$2

	gcc -g -O0 -o "$bin" "$src"
}

record_trace()
{
	local bin=$1
	local data=$2
	local script=$3

	perf record -o "$data" --per-thread -e cs_etm// -- "$bin" >/dev/null 2>&1 &&
	perf script --itrace=g16i10il64 -i "$data" > "$script"
}

check_regex()
{
	local name=$1
	local regex=$2
	local script=$3

	if grep -Pzo "$regex" "$script" >/dev/null; then
		echo "Test $name: PASS"
	else
		echo "Test $name: FAIL"
		glb_err=1
	fi
}

run_test()
{
	local name=$1
	local src=$tmpdir/$name.S
	local bin=$tmpdir/$name
	local data=$tmpdir/perf.$name.data
	local script=$tmpdir/perf.$name.script
	local regex

	"${name}_src" "$src"

	if ! build_test_program "$src" "$bin"; then
		echo "$name: build failed"
		glb_err=1
		return
	fi

	if ! record_trace "$bin" "$data" "$script"; then
		echo "$name: perf record/script failed"
		glb_err=1
		return
	fi

	regex=$("${name}_push_regex")
	check_regex "${name} push" "$regex" "$script"

	regex=$("${name}_pop_regex")
	check_regex "${name} pop" "$regex" "$script"
}

callchain_src()
{
	cat > "$1" <<'EOF_C'
/* callchain.S */
	.text

	.global do_svc
	.type do_svc, %function
do_svc:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

	mov	x0, #1
	adr	x1, msg
	mov	x2, #23
	mov	x8, #64

	nop
	nop	// Pad nops for 9 insns before svc

	b	1f
1:
	svc	#0

	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop	// Pad nops for 10 insns after svc

	ldp	x29, x30, [sp], #16
	ret
	.size do_svc, .-do_svc

	.global foo
	.type foo, %function
foo:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	nop
	nop
	nop
	nop
	nop
	nop
	nop	// Pad nops for 9 insns before call

	bl	do_svc

	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop	// Pad nops for 10 insns after call

	ldp	x29, x30, [sp], #16
	ret
	.size foo, .-foo

	.global main
	.type main, %function
main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

	bl	foo

	mov	w0, #0
	ldp	x29, x30, [sp], #16
	.size main, .-main
	ret

	.section .rodata
msg:
	.asciz	"hello from svc syscall\n"
EOF_C
}

callchain_push_regex()
{
	printf '%s' \
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x[[:xdigit:]]+ \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)\n'\
'([[:space:]]+[[:xdigit:]]+ .*\n)*'\
'\n'\
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ do_svc\+0x[[:xdigit:]]+ \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)\n'\
'([[:space:]]+[[:xdigit:]]+ .*\n)*'\
'\n'\
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ (vectors|el.*_64_sync)\+0x[[:xdigit:]]+ \(\[kernel\.kallsyms\]\)\n'\
'[[:space:]]+[[:xdigit:]]+ do_svc\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)\n'
}

callchain_pop_regex()
{
	printf '%s' \
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ ret_to_user\+0x[[:xdigit:]]+ \(\[kernel\.kallsyms\]\)\n'\
'[[:space:]]+[[:xdigit:]]+ do_svc\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)\n'\
'([[:space:]]+[[:xdigit:]]+ .*\n)*'\
'\n'\
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ do_svc\+0x[[:xdigit:]]+ \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x28 \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)' \
'([[:space:]]+[[:xdigit:]]+ .*\n)*'\
'\n'\
'callchain[[:space:]]+[0-9]+ \[[0-9]+\][[:space:]]+10 instructions:[[:space:]]*\n'\
'[[:space:]]+[[:xdigit:]]+ foo\+0x[[:xdigit:]]+ \(.*/callchain\)\n'\
'[[:space:]]+[[:xdigit:]]+ main\+0xc \(.*/callchain\)'
}

skip_if_system_is_not_ready || exit 2

run_test "callchain"

exit $glb_err
