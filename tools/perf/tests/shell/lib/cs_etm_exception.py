#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Decode generated ETMv4 recordings without a PMU or an AArch64 toolchain.

The instruction bytes and trace packets are constructed here, including both
encodings of an exception address: a preferred return address on its own, and
one that is also the target of a preceding branch. All code mappings are local
test files. Exception levels are traced, but use user mappings to avoid needing
a matching kernel image or privileged access to the test machine.
"""

import argparse
from pathlib import Path
import re
import struct
import subprocess
import tempfile


PID = 42
EVENT_ID = 100
PMU_TYPE = 13
TRACE_ID = 0x10
NOP = 0xd503201f
B_SELF = 0x14000000
BLR_X5 = 0xd63f00a0
ERET = 0xd69f03e0
SVC = 0xd4000001
HVC = 0xd4000002
SMC = 0xd4000003
ATOM_E = b'\xf7'
ATOM_N = b'\xf6'
TRACE_ON = b'\x04'
EXCEPTION_RETURN = b'\x07'


def u64(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


def u32(*values):
    return struct.pack('<' + 'I' * len(values), *values)


def align(data):
    return data + bytes(-len(data) % 8)


def record(kind, misc, data):
    return struct.pack('<IHH', kind, misc, len(data) + 8) + data


def sample_id(time=1):
    return u32(PID, PID) + u64(time, EVENT_ID) + u32(0, 0) + u64(EVENT_ID)


def address(addr, el=None, aarch64=True):
    # Address Long (64-bit, IS0), optionally with Context, IHI 0064.
    data = bytes([0x9d if el is None else 0x85,
                  (addr >> 2) & 0x7f, (addr >> 9) & 0x7f])
    data += bytes((addr >> shift) & 0xff for shift in range(16, 64, 8))
    if el is not None:
        # NS, SF (AArch64), EL, and a four-byte context ID.
        data += bytes([0xa0 | (0x10 if aarch64 else 0) | el]) + u32(PID)
    return data


def trace_start(addr=0x1000, el=0, aarch64=True):
    # A-Sync, Trace Info (no optional fields), Trace On, address/context.
    return bytes(11) + b'\x80\x01\x00' + TRACE_ON + address(addr, el, aarch64)


def exception(kind, addr, shared=False, el=None):
    # Bit 6 means the following address also resolves a preceding branch.
    return bytes([6, (kind << 1) | (0x40 if shared else 1)]) + address(addr, el)


class Recording:
    def __init__(self, directory, name, code, chunks, base=0x1000, aarch64=True, ete=False):
        self.name = name
        self.path = directory / (name + '.data')
        code_path = directory / (name + '.elf')
        code = u32(*code)
        # Minimal ELF64 or ELF32 with an executable PT_LOAD at file offset 4096.
        elf = bytearray(4096)
        if aarch64:
            elf[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
            struct.pack_into('<HHIQQQIHHHHHH', elf, 16, 2, 183, 1, base,
                             64, 0, 0, 64, 56, 1, 64, 0, 0)
            struct.pack_into('<IIQQQQQQ', elf, 64, 1, 5, 4096, base, base,
                             len(code), len(code), 4096)
        else:
            elf[:16] = b'\x7fELF\x01\x01\x01' + bytes(9)
            struct.pack_into('<HHIIIIIHHHHHH', elf, 16, 2, 40, 1, base,
                             52, 0, 0, 52, 32, 1, 40, 0, 0)
            struct.pack_into('<IIIIIIII', elf, 52, 1, 4096, base, base,
                             len(code), len(code), 5, 4096)
        code_path.write_bytes(elf + code)

        # IP, TID, TIME, ID, CPU, PERIOD, IDENTIFIER; sample_id_all.
        sample_type = 1 | 2 | 4 | 64 | 128 | 256 | 65536
        attr = bytearray(128)
        struct.pack_into('<IIQQQQQ', attr, 0, PMU_TYPE, 128, 0, 1,
                         sample_type, 0, 1 << 18)
        attrs = attr + u64(104, 8)
        data_offset = 112 + len(attrs)

        # cs-etm metadata v1, one ETMv4 CPU, context IDs, no timestamps.
        # CONFIGR, TRACEIDR, IDR0, IDR1, IDR2, IDR8, AUTHSTATUS, TS_SOURCE.
        metadata = [1, (PMU_TYPE << 32) | 1, 0, 0x4040404040404040, 0, 8,
                    1 << 6, TRACE_ID, 0x28000ea1, 0x4100f400, 0x488, 0, 0, 0]
        if ete:
            # ETE adds DEVARCH before TS_SOURCE; no speculative P0 elements.
            metadata = [1, (PMU_TYPE << 32) | 1, 0, 0x5050505050505050, 0, 9,
                        1 << 6, TRACE_ID, 0x2801cea1, 0x4100fff0, 0xd0001088,
                        0, 0, 0x47705a13, 0]
        records = [record(70, 0, u32(3, 0) + u64(*metadata)),
                   record(3, 0, u32(PID, PID) + align(b'exception-test\0') + sample_id()),
                   record(1, 2, u32(PID, PID) + u64(base, len(code), 4096) +
                          align(str(code_path).encode() + b'\0') + sample_id())]
        index = []
        offset = 0
        for number, payload in enumerate(chunks):
            payload = align(payload)
            # PERF_RECORD_AUX with PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW.
            records.append(record(11, 0, u64(offset, len(payload), 0x100) +
                                  sample_id(100 + number)))
            index.append(data_offset + sum(map(len, records)))
            # AUXTRACE payload is outside the 48-byte record header.
            records.append(record(71, 0, u64(len(payload), offset, 100 + number) +
                                  u32(0, PID, 0, 0)) + payload)
            offset += len(payload)
        data = b''.join(records)
        features = {6: u32(8) + b'arm64\0\0\0', 7: u32(1, 1),
                    16: u32(1, PMU_TYPE, 8) + b'cs_etm\0\0',
                    18: u64(len(index), *(v for i in index for v in (i, 48)))}
        sections = b''
        feature_data = b''
        for _, payload in sorted(features.items()):
            sections += u64(data_offset + len(data) + 16 * len(features) +
                            len(feature_data), len(payload))
            feature_data += payload
        header = u64(0x32454c4946524550, 104, 144, 112, len(attrs), data_offset,
                     len(data), 0, 0, sum(1 << n for n in features), 0, 0, 0)
        self.path.write_bytes(header + u64(EVENT_ID) + attrs + data + sections + feature_data)

    def script(self, perf, itrace, fields):
        args = [perf, 'script', '-i', str(self.path), '--itrace=' + itrace, '-F', fields]
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=False)
        if result.returncode:
            raise RuntimeError(f'{self.name}: {result.stderr}')
        return result.stdout

    def branches(self, perf):
        result = []
        for line in self.script(perf, 'b', 'ip,addr,flags,insnlen').splitlines():
            match = re.fullmatch(r'\s*(.*?)\s+([0-9a-f]+) =>\s+([0-9a-f]+) ilen: (\d+)', line)
            if not match:
                raise RuntimeError(f'{self.name}: unexpected branch output: {line!r}')
            flags, source, target, size = match.groups()
            result.append((int(source, 16), int(target, 16), ' '.join(flags.split()), int(size)))
        return result

    def instructions(self, perf, itrace='i1i'):
        return [(int(ip, 16), int(period)) for period, ip in
                (line.split() for line in self.script(perf, itrace, 'ip,period').splitlines())]

    def callchains(self, perf):
        output = self.script(perf, 'i1ig', 'ip,period')
        return [[int(ip, 16) for ip in re.findall(r'^\s+([0-9a-f]+) \[unknown\]', block, re.M)]
                for block in output.strip().split('\n\n')]

    def first_handler_branches(self, perf, handler=0x2000):
        output = self.script(perf, 'i1il', 'ip,period,brstack')
        for line in output.splitlines():
            if line.split()[:2] == ['1', f'{handler:x}']:
                return [(int(source, 16), int(target, 16)) for source, target in
                        re.findall(r'0x([0-9a-f]+)/0x([0-9a-f]+)/', line)]
        raise RuntimeError(f'{self.name}: no instruction sample in handler')


def equal(name, got, expected):
    if got != expected:
        for index, (actual, want) in enumerate(zip(got, expected)):
            if actual != want:
                raise AssertionError(f'{name}: entry {index}: got {actual}, expected {want}')
        raise AssertionError(f'{name}: got {len(got)} entries, expected {len(expected)}')


def test(directory, perf):
    trace_begin = (0, 0x1000, 'tr strt jmp', 0)
    handler_branch = (0x2000, 0x2000, 'jmp', 4)
    # name, opcode, preferred return, exception type, branch address encoding,
    # atom, source EL, handler EL, branch flag, exception source, fetched opcode size.
    # Fetching an opcode does not mean the interrupted instruction executed.
    cases = [
        ('untaken-irq', 0x54000809, 0x1004, 14, False, ATOM_N, 0, 1, 'hw int', 0x1004, 4),
        ('untaken-fiq', 0x54000809, 0x1004, 15, False, ATOM_N, 0, 1, 'hw int', 0x1004, 4),
        ('indirect-irq', BLR_X5, 0x1100, 14, True, ATOM_E, 0, 1, 'hw int', 0x1100, 4),
        ('direct-irq', 0x14000040, 0x1100, 14, False, ATOM_E, 0, 1, 'hw int', 0x1100, 4),
        ('data-fault', NOP, 0x1004, 12, False, b'', 0, 1, 'int', 0x1004, 4),
        ('svc', SVC, 0x1004, 2, False, b'', 0, 1, 'syscall', 0x1000, 4),
        ('hvc', HVC, 0x1004, 2, False, b'', 1, 2, 'int', 0x1000, 4),
        ('smc', SMC, 0x1004, 2, False, b'', 1, 3, 'int', 0x1000, 4),
        ('trapped-hvc', HVC, 0x1000, 3, False, b'', 1, 2, 'int', 0x1000, 4),
        ('trapped-smc', SMC, 0x1000, 3, False, b'', 1, 2, 'int', 0x1000, 4),
        ('instruction-fault', BLR_X5, 0x3000, 11, True, ATOM_E, 0, 1, 'int', 0x3000, 0),
    ]
    for name, first, ret, kind, shared, atom, el, handler_el, flags, source, size in cases:
        code = [NOP] * 2048
        code[0], code[1], code[1024] = first, 0xf9400020, B_SELF
        trace = trace_start(el=el) + atom + exception(kind, ret, shared)
        trace += address(0x2000, handler_el) + ATOM_E * 2
        data = Recording(directory, name, code, [trace])
        entry = (source, 0x2000, flags, size)
        preceding = []
        if atom == ATOM_E:
            preceding = [(0x1000, ret, 'call' if first == BLR_X5 else 'jmp', 4)]
        equal(name, data.branches(perf), [trace_begin] + preceding + [entry, handler_branch])
        instruction_ips = ([] if kind == 3 else [0x1000]) + [0x2000, 0x2000]
        equal(name + ' instructions', data.instructions(perf), [(ip, 1) for ip in instruction_ips])
        chain = [0x2000, ret] + ([0x1004] if first == BLR_X5 else [])
        equal(name + ' callchains', data.callchains(perf),
              ([] if kind == 3 else [[0x1000]]) + [chain, chain])
        equal(name + ' last branches', data.first_handler_branches(perf),
              [(source, 0x2000)] + [(branch[0], branch[1]) for branch in preceding])
        print(f'PASS: {name}')

    for first, atom, shared, ret, name in [
        (0x54000809, ATOM_N, False, 0x1004, 'ete-untaken-irq'),
        (BLR_X5, ATOM_E, True, 0x1100, 'ete-indirect-irq'),
    ]:
        code = [NOP] * 2048
        code[0], code[1024] = first, B_SELF
        trace = trace_start() + atom + exception(14, ret, shared)
        trace += address(0x2000, 1) + ATOM_E * 2
        data = Recording(directory, name, code, [trace], ete=True)
        preceding = [(0x1000, ret, 'call', 4)] if shared else []
        equal(name, data.branches(perf), [trace_begin] + preceding +
              [(ret, 0x2000, 'hw int', 4), handler_branch])
        print(f'PASS: {name}')

    code = [NOP] * 2048
    code[0], code[1024], code[1028] = BLR_X5, B_SELF, B_SELF
    trace = trace_start() + ATOM_E + address(0x1100)
    trace += exception(14, 0x1100) + address(0x2000, 1) + ATOM_E * 2
    data = Recording(directory, 'indirect-separate-address', code, [trace])
    equal(data.name, data.branches(perf), [trace_begin, (0x1000, 0x1100, 'call', 4),
                                         (0x1100, 0x2000, 'hw int', 4), handler_branch])
    print(f'PASS: {data.name}')

    trace = trace_start() + ATOM_E + address(0x4000, 0) + ATOM_E
    trace += exception(14, 0x4004) + address(0x2000, 1) + ATOM_E * 2
    data = Recording(directory, 'unmapped-gap', code, [trace])
    equal(data.name, data.branches(perf), [trace_begin, (0x1000, 0, 'tr end call', 4),
                                         (0, 0x4004, 'tr strt jmp', 0),
                                         (0x4004, 0x2000, 'hw int', 0), handler_branch])
    equal(data.name + ' history', data.first_handler_branches(perf), [(0x4004, 0x2000)])
    print(f'PASS: {data.name}')

    code[0] = 0x54000809
    before_gap = trace_start() + ATOM_N + exception(14, 0x1004)
    for name, chunks in [
        ('trace-on-gap', [before_gap + TRACE_ON + address(0x2000, 1) + ATOM_E * 2]),
        ('aux-gap', [before_gap, trace_start(0x2000, 1) + ATOM_E * 2]),
    ]:
        data = Recording(directory, name, code, chunks)
        equal(name, data.branches(perf), [trace_begin, (0x1004, 0, 'tr end hw int', 4),
                                          (0, 0x2000, 'tr strt jmp', 0), handler_branch])
        equal(name + ' history', data.first_handler_branches(perf), [])
        print(f'PASS: {name}')

    data = Recording(directory, 'exception-at-end', code,
                     [before_gap + address(0x2000, 1)])
    equal(data.name + ' no final instruction sample', data.instructions(perf, 'i100il'), [])
    equal(data.name + ' no stale destination', data.branches(perf), [trace_begin])
    print(f'PASS: {data.name}')

    # Emit the call and periodic instruction sample, but no sample at the IRQ PC.
    branch_code = list(code)
    branch_code[0] = BLR_X5
    trace = trace_start() + ATOM_E + exception(14, 0x1100, True)
    data = Recording(directory, 'indirect-exception-at-end', branch_code,
                     [trace + address(0x2000, 1)])
    equal(data.name, data.branches(perf), [trace_begin, (0x1000, 0x1100, 'call', 4)])
    equal(data.name + ' instruction sample', data.instructions(perf, 'i1il'), [(0x1000, 1)])
    equal(data.name + ' no final instruction sample', data.instructions(perf, 'i100il'), [])
    print(f'PASS: {data.name}')

    # Final samples still come from nonempty ranges at a block end or trace gap.
    for name, trace in [
        ('nonempty-range-at-end', trace_start() + ATOM_N),
        ('nonempty-range-before-gap', trace_start() + ATOM_N + TRACE_ON),
    ]:
        data = Recording(directory, name, code, [trace])
        equal(name + ' final instruction', data.instructions(perf, 'i100il'), [(0x1000, 1)])
        print(f'PASS: {name}')

    trace = trace_start() + exception(14, 0x1000) + address(0x2000, 1)
    data = Recording(directory, 'exception-before-instructions', code, [trace])
    equal(data.name, data.branches(perf), [trace_begin])
    equal(data.name + ' no instruction sample', data.instructions(perf, 'i100il'), [])
    print(f'PASS: {data.name}')

    trace = before_gap + address(0x2000, 1) + exception(11, 0x2000)
    trace += address(0x2010, 1) + ATOM_E * 2
    data = Recording(directory, 'nested-entry-fault', code, [trace])
    equal(data.name, data.branches(perf), [trace_begin, (0x1004, 0x2000, 'hw int', 4),
                                         (0x2000, 0x2010, 'int', 4),
                                         (0x2010, 0x2010, 'jmp', 4)])
    equal(data.name + ' callchains', data.callchains(perf),
          [[0x1000], [0x2010, 0x2000, 0x1004], [0x2010, 0x2000, 0x1004]])
    print(f'PASS: {data.name}')

    trace = before_gap + address(0x2000, 1) + exception(11, 0x2000) + address(0x2010, 1)
    data = Recording(directory, 'nested-exception-at-end', code, [trace])
    equal(data.name, data.branches(perf), [trace_begin, (0x1004, 0x2000, 'hw int', 4)])
    equal(data.name + ' no final instruction sample', data.instructions(perf, 'i100il'), [])
    print(f'PASS: {data.name}')

    code[1024] = ERET
    for syscall in (False, True):
        code[0] = SVC if syscall else 0x54000809
        trace = trace_start() + (b'' if syscall else ATOM_N)
        trace += exception(2 if syscall else 14, 0x1004) + address(0x2000, 1)
        trace += ATOM_E + EXCEPTION_RETURN + exception(14, 0x1004, True, el=0)
        trace += address(0x2010, 1) + ATOM_E * 2
        data = Recording(directory, 'svc-eret-irq' if syscall else 'eret-irq', code, [trace])
        equal(data.name, data.branches(perf), [trace_begin,
              (0x1000 if syscall else 0x1004, 0x2000, 'syscall' if syscall else 'hw int',
               4),
              (0x2000, 0x1004, 'sysret' if syscall else 'iret', 4),
              (0x1004, 0x2010, 'hw int', 4), (0x2010, 0x2010, 'jmp', 4)])
        equal(data.name + ' callchains', data.callchains(perf),
              [[0x1000], [0x2000, 0x1004], [0x2010, 0x1004], [0x2010, 0x1004]])
        print(f'PASS: {data.name}')

    code[0], code[1], code[2] = NOP, 0xf9400020, B_SELF
    for target in (0x1004, 0x1008):
        trace = trace_start() + exception(12, 0x1004) + address(0x2000, 1)
        trace += ATOM_E + EXCEPTION_RETURN + address(target, 0) + ATOM_E * 2
        data = Recording(directory, f'fault-return-{target:x}', code, [trace])
        equal(data.name, data.branches(perf), [trace_begin, (0x1004, 0x2000, 'int', 4),
                                             (0x2000, target, 'iret', 4),
                                             (0x1008, 0x1008, 'jmp', 4)])
        if target == 0x1004:
            equal(data.name + ' callchains', data.callchains(perf),
                  [[0x1000], [0x2000, 0x1004], [0x1004], [0x1008], [0x1008]])
        print(f'PASS: {data.name}')

    code[0], code[1024] = 0x54000009, B_SELF  # B.LS to itself
    # Put the range, exception and context on either side of a decoder queue full.
    for count in range(1019, 1025):
        trace = trace_start() + ATOM_E * count + ATOM_N + exception(14, 0x1004)
        trace += address(0x2000, 1) + ATOM_E * 2
        data = Recording(directory, f'queue-boundary-{count}', code, [trace])
        equal(data.name, data.branches(perf), [trace_begin] + [(0x1000, 0x1000, 'jcc', 4)] * count +
              [(0x1004, 0x2000, 'hw int', 4), handler_branch])
        print(f'PASS: {data.name}')

    # AArch32 uses the existing source attribution; do not apply AArch64 ELR rules.
    for syscall in (False, True):
        code = [0xe1a00000] * 2048
        code[0] = 0xef000000 if syscall else 0x0a00003e
        code[1024] = 0xeafffffe
        trace = trace_start(aarch64=False) + (b'' if syscall else ATOM_N)
        trace += exception(2 if syscall else 14, 0x1004)
        trace += address(0x2000, 1, False) + ATOM_E * 2
        data = Recording(directory, 'aarch32-svc' if syscall else 'aarch32-irq',
                         code, [trace], aarch64=False)
        equal(data.name, data.branches(perf), [trace_begin,
              (0x1000, 0x2000, 'syscall' if syscall else 'hw int', 4), handler_branch])
        print(f'PASS: {data.name}')

    # Reproduce the motivating B.LS / B.NE loop, with a local vector mapping.
    base = 0x400000
    code = [NOP] * (0x3000 // 4)
    for offset, instruction in [(0xf4, 0xeb02003f), (0xf8, 0x54000109),
                                (0xfc, 0xd282f2c2), (0x108, 0x54ffff61),
                                (0x1c80, 0x14000003), (0x1ca4, 0x14000241),
                                (0x25a8, B_SELF)]:
        code[offset // 4] = instruction
    trace = trace_start(base + 0xf4) + (ATOM_N + ATOM_E) * 2 + ATOM_N
    trace += exception(14, base + 0xfc) + address(base + 0x1c80, 1) + ATOM_E * 3
    data = Recording(directory, 'untaken-loop-example', code, [trace], base=base)
    equal(data.name, data.branches(perf), [(0, 0x4000f4, 'tr strt jmp', 0),
          (0x400108, 0x4000f4, 'jcc', 4), (0x400108, 0x4000f4, 'jcc', 4),
          (0x4000fc, 0x401c80, 'hw int', 4), (0x401c80, 0x401c8c, 'jmp', 4),
          (0x401ca4, 0x4025a8, 'jmp', 4)])
    print(f'PASS: {data.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--perf', default='perf')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='perf-cs-etm-exception-') as directory:
        test(Path(directory), args.perf)


if __name__ == '__main__':
    main()
