.. SPDX-License-Identifier: GPL-2.0

================
CoreSight - Perf
================

    :Author:   Carsten Haitzler <carsten.haitzler@arm.com>
    :Date:     June 29th, 2022

Perf is able to locally access CoreSight trace data and store it to the
output perf data files. This data can then be later decoded to give the
instructions that were traced for debugging or profiling purposes. You
can log such data with a perf record command like::

   perf record -e cs_etm//u testbinary

This would run some test binary (testbinary) until it exits and record
a perf.data trace file. That file would have AUX sections if CoreSight
is working correctly. You can dump the content of this file as
readable text with a command like::

   perf report --stdio --dump -i perf.data

You should find some sections of this file have AUX data blocks like::

   0x1e78 [0x30]: PERF_RECORD_AUXTRACE size: 0x11dd0  offset: 0  ref: 0x1b614fc1061b0ad1  idx: 0  tid: 531230  cpu: -1

   . ... CoreSight ETM Trace data: size 73168 bytes
           Idx:0; ID:10;   I_ASYNC : Alignment Synchronisation.
             Idx:12; ID:10;  I_TRACE_INFO : Trace Info.; INFO=0x0 { CC.0 }
             Idx:17; ID:10;  I_ADDR_L_64IS0 : Address, Long, 64 bit, IS0.; Addr=0x0000000000000000;
             Idx:26; ID:10;  I_TRACE_ON : Trace On.
             Idx:27; ID:10;  I_ADDR_CTXT_L_64IS0 : Address & Context, Long, 64 bit, IS0.; Addr=0x0000FFFFB6069140; Ctxt: AArch64,EL0, NS;
             Idx:38; ID:10;  I_ATOM_F6 : Atom format 6.; EEEEEEEEEEEEEEEEEEEEEEEE
             Idx:39; ID:10;  I_ATOM_F6 : Atom format 6.; EEEEEEEEEEEEEEEEEEEEEEEE
             Idx:40; ID:10;  I_ATOM_F6 : Atom format 6.; EEEEEEEEEEEEEEEEEEEEEEEE
             Idx:41; ID:10;  I_ATOM_F6 : Atom format 6.; EEEEEEEEEEEN
             ...

If you see these above, then your system is tracing CoreSight data
correctly.

To compile perf with CoreSight support in the tools/perf directory do::

    make CORESIGHT=1

This requires OpenCSD to build. You may install distribution packages
for the support such as libopencsd and libopencsd-dev or download it
and build yourself. Upstream OpenCSD is located at:

  https://github.com/Linaro/OpenCSD

For complete information on building perf with CoreSight support and
more extensive usage look at:

  https://github.com/Linaro/OpenCSD/blob/master/HOWTO.md


Kernel CoreSight Support
------------------------

You will also want CoreSight support enabled in your kernel config.
Ensure it is enabled with::

   CONFIG_CORESIGHT=y

There are various other CoreSight options you probably also want
enabled like::

   CONFIG_CORESIGHT_LINKS_AND_SINKS=y
   CONFIG_CORESIGHT_LINK_AND_SINK_TMC=y
   CONFIG_CORESIGHT_CATU=y
   CONFIG_CORESIGHT_SINK_TPIU=y
   CONFIG_CORESIGHT_SINK_ETBV10=y
   CONFIG_CORESIGHT_SOURCE_ETM4X=y
   CONFIG_CORESIGHT_CTI=y
   CONFIG_CORESIGHT_CTI_INTEGRATION_REGS=y

Please refer to the kernel configuration help for more information.

Fine-grained tracing with AUX pause and resume
----------------------------------------------

Arm CoreSight may generate a large amount of hardware trace data, which
will lead to overhead in recording and distract users when reviewing
profiling result. To mitigate the issue of excessive trace data, Perf
provides AUX pause and resume functionality for fine-grained tracing.

The AUX pause and resume can be triggered by associated events. These
events can be ftrace tracepoints (including static and dynamic
tracepoints) or PMU events (e.g. CPU PMU cycle event). To create a perf
session with AUX pause / resume, three configuration terms are
introduced:

- "aux-action=start-paused": it is specified for the cs_etm PMU event to
  launch in a paused state.
- "aux-action=pause": an associated event is specified with this term
  to pause AUX trace.
- "aux-action=resume": an associated event is specified with this term
  to resume AUX trace.

Example for triggering AUX pause and resume with ftrace tracepoints::

  perf record -e cs_etm/aux-action=start-paused/k,syscalls:sys_enter_openat/aux-action=resume/,syscalls:sys_exit_openat/aux-action=pause/ ls

Example for triggering AUX pause and resume with PMU event::

  perf record -a -e cs_etm/aux-action=start-paused/k \
        -e cycles/aux-action=pause,period=10000000/ \
        -e cycles/aux-action=resume,period=1050000/ -- sleep 1

Context-sensitive sampled PGO (CSSPGO) profiling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A callchain-bearing pause event can be combined with the branch history from
its preceding ETM trace window. This provides the synchronized callchain and
branch stack consumed by context-sensitive PGO tools without continuously
recording ETM trace for a long-running process.

For example, record user-space ETM trace, resume it periodically, and pause it
with a cycle event that also captures a frame-pointer callchain::

  perf record -T \
        -e cs_etm/aux-action=start-paused,timestamp/u \
        -e cycles/aux-action=resume,period=8350251/u \
        -e cycles/aux-action=pause,period=100003,call-graph=fp/u \
        -- ./workload

The two cycle events count independently. With pause period ``P`` and resume
period ``R``, each trace window is approximately 0 to ``P`` cycles long, so the
average duty cycle is ``P / (2 * R)``. The periods above give about 0.6% duty.

Do not make ``R`` an integer multiple of ``P``: coincident pause and resume
interrupts can produce zero-length windows. Choosing ``R`` near
``(k + 1/2) * P``, as above, moves the resume phase across the pause interval.
Pause events that fire while ETM is already paused have no branch history; the
dlfilter below removes those samples.

The ``-T`` option timestamps the pause samples, while ``timestamp`` enables
ETM timestamp packets. Both are required to correlate the sample with ETM
trace. This mode also requires virtual ETM timestamps correlated to perf time
and a callchain on the pause event. Use ``call-graph=dwarf`` instead of
``call-graph=fp`` when the workload does not preserve frame pointers.

Tuning duty cycle
^^^^^^^^^^^^^^^^^

The example above favors low recording overhead for fleet collection. With
independent counters, ``P / R`` is the nominal window ratio while
``P / (2 * R)`` is the expected average ETM-on duty. For ``P = 100003``, two
measured Neoverse V2 operating points are:

- Fleet collection: ``R = 8350251``, 1.2% nominal ratio and 0.6% average duty.
- Targeted profiling: ``R = 1050031``, 9.5% nominal ratio and 4.8% average duty.

AUX buffer size must also scale with trace volume. A 128 KiB AUX buffer worked
at 0.6% duty but was unstable at some higher-duty points, where it increased
output size or overran and reduced useful-sample yield. Use 4 MiB as a
conservative starting point around ``R/P = 6.7`` to ``12.5``. These values are
workload and platform dependent; verify useful samples per MiB and lost AUX
records when tuning another system.

Add up to 64 decoded ETM branches to each existing pause sample and emit the
hybrid samples in the regular perf-script format::

  perf script -i perf.data --itrace=L64 \
        --dlfilter=dlfilter-nonempty-brstack.so > perf.script

The ``dlfilter-nonempty-brstack.so`` filter drops samples that ended up with
no branch history at all, for example samples from a thread that was never
traced, or samples recorded before the first or after the last trace window.
It is built and installed with perf's other dlfilters.

Decode branch history from AUX samples
--------------------------------------

With a kernel that supports CoreSight AUX sampling, record a TRBE trace
window inside each cycle sample::

  perf record --aux-sample=8192 -e '{cs_etm//u,cycles/period=100003/u}' \
        -- ./workload
  perf script --itrace=G16L64 -F comm,pid,tid,cpu,event,ip,brstack

``G16`` adds a reconstructed callchain and ``L64`` adds up to 64 branches.
Either option can be used alone. Existing callchains and branch stacks are
preserved. Without an explicit ``--itrace`` option, both are enabled for AUX
samples. Decoded history is available in ``perf script`` and ``perf report``.
Synthesizing instruction events and saving reconstructed callchains with
``perf inject`` are not supported.

AUX sampling supports unformatted, per-CPU TRBE trace. Each sample selects
its CPU's decoder and starts a fresh trace window. The window already belongs
to the sample, so ETM timestamps are not required for attribution. Samples
without decodable history receive no reconstructed stack.
CPU-wide recordings must enable context IDs to distinguish tasks within a
window; the default recording setup enables them.

Callchains cover only calls visible in the captured window; callers before
the first synchronization point cannot be recovered. The existing late-sample
helpers trim intervening kernel execution, but cannot precisely remove all
execution between the sampled instruction and the trace source stopping.
Formatted sinks and guest samples are not supported.

Perf test - Verify kernel and userspace perf CoreSight work
-----------------------------------------------------------

There are a set of Perf tests for CoreSight which can be run with::

  sudo perf test coresight
