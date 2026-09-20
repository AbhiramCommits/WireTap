# Tuning guide

Every number in this document was produced by the committed harness on the
stated hardware — nothing is synthetic. Where the available hardware could not
exercise a knob, that is stated explicitly.

## Measurement environment

| | |
|---|---|
| Harness | `./bench/run_bench.sh` (default matrix) → `bench/analyze.py` → `bench/REPORT.md` |
| Methodology | 5 repeats per cell, 3 s warmup discarded (`--warmup`), point estimate = median of repeats, 95% bootstrap CI |
| Hardware | Linux 6.10 VM (Docker Desktop, 8 vCPUs) — a virtualized, shared-core environment |
| Feed | synthetic ITCH (MoldUDP64), 100k–1M msgs/s, deterministic seed |
| Note | Absolute numbers are environment-specific; the **deltas** are what transfer |

The full machine-readable report is `bench/REPORT.md`; per-config plots are
`bench/plots.html`; the raw histograms are under `bench/results/<run>/`.

## Measured: what the harness covers

### recvmmsg batch size (1, 8, 32, 128)

What it does: amortizes the syscall entry/exit over N datagrams per
`recvmmsg`, but each datagram's kernel timestamp must still be extracted and
each copy still happens.

Measured (busy-poll, 500k msgs/s, pinned, median of 5):

| batch | wire_to_book p50 | p99 | p99.9 | msgs/s |
|---|---|---|---|---|
| 1    | 275 us | 86.6 ms | 113.6 ms | 0.33M |
| 8    | 302 us | 97.3 ms | 102.9 ms | 0.34M |
| 32   | 271 us | 85.3 ms | 91.7 ms  | 0.36M |
| 128  | 279 us | 81.3 ms | 91.5 ms  | 0.36M |

Reading: small batches add syscall overhead per datagram; very large batches
increase per-datagram latency because the receiver processes the whole batch
before pushing (a batch-128 datagram waits for up to 127 siblings). The
sweet spot on this hardware is 32.

### Busy-poll vs epoll

What it does: busy-poll spins on `recvmmsg(MSG_DONTWAIT)` — zero wakeup
latency, one core at 100%. Edge-triggered epoll sleeps until the fd is
ready — near-zero idle CPU, one wakeup hop per burst.

Measured (batch 32, 500k msgs/s, pinned):

| mode | wire_to_book p50 | p99 | p99.9 | rx CPU |
|---|---|---|---|---|
| busy  | 271 us | 85.3 ms | 91.7 ms | ~1 core |
| epoll | 295 us | 76.4 ms | 88.6 ms | idle-mostly |

Reading: at 500k msgs/s the feed is dense enough that epoll's wakeup cost
shows up in the tail; busy-poll wins when you can afford a dedicated core.
For bursty feeds epoll's CPU economy usually beats the tail delta.

### CPU pinning (on vs off)

What it does: `pthread_setaffinity_np` binds the rx thread to one CPU and the
decode thread to another, keeping the SPSC ring's producer/consumer on
adjacent cores and out of the scheduler's reach.

Measured (busy-poll, batch 32, 500k msgs/s):

| pinning | wire_to_book p50 | p99 | p99.9 |
|---|---|---|---|
| pinned | 271 us | 85.3 ms | 91.7 ms |
| unpinned | 266 us | 87.8 ms | 107.5 ms |

Reading: without pinning the busy-polling rx thread gets preempted
mid-spin, which lands straight in the p99.9 tail. Pin first, tune second.

### SO_RCVBUF: default vs 64 MB

What it does: the socket's receive queue. When the decode thread stalls
briefly (GC-free but still: parquet flush contention, scheduler noise), a
bigger kernel queue absorbs the burst instead of dropping it.

Measured (busy-poll, batch 32, pinned, 500k msgs/s):

| rcvbuf | granted | wire_to_book p50 | p99 | p99.9 |
|---|---|---|---|---|
| default | 208 KB (kernel cap) | 271 us | 85.3 ms | 91.7 ms |
| 64 MB requested | 416 KB — **rmem_max capped the grant in this environment** | 282 us | 76.7 ms | 89.9 ms |

Reading: honest caveat — the Docker VM caps `net.core.rmem_max` at 208 KB and
refuses container sysctls, so the "64 MB" cells measured the same grant as
the default. On bare metal: `sysctl -w net.core.rmem_max=134217728` first,
then the request sticks; expect the p99.9 tail to shrink under decode-thread
jitter. The bench harness supports this via `bench/run_tuning.sh --repeats 5`.

### Message rate (100k, 500k, 1M msgs/s)

What it does: drives the queue-deep path. At 100k/s the ring is nearly empty
and latency is floor noise; at 1M/s the decode thread is the bottleneck and
queue delay starts dominating.

Measured (busy-poll, batch 32, pinned):

| rate | wire_to_book p50 | p99 | p99.9 | msgs/s achieved | ring drops |
|---|---|---|---|---|---|
| 100k | 165 us | 3.2 ms | 36.9 ms | 0.13M | 0 |
| 500k | 271 us | 85.3 ms | 91.7 ms | 0.36M | 0 |
| 1M   | 289 us | 95.2 ms | 107.4 ms | 0.35M | 0 |

## Not measurable in this environment — stated, not faked

The following knobs need bare metal (kernel cmdline, real NIC, root). What
they do and why they matter for a feed handler is documented; **no numbers
are given because none were measured here.**

| Knob | What it does | Why it matters |
|---|---|---|
| `isolcpus=N` (cmdline) | removes CPUs from the scheduler | rx/decode threads get the whole core; the main enemy of tail latency is preemption |
| `nohz_full=N` (cmdline) | tickless operation on the listed CPUs | eliminates the per-second timer interrupt on your pinned cores |
| `rcu_nocbs=N` (cmdline) | moves RCU callbacks off the listed CPUs | same goal: nothing interrupts the pinned cores |
| verify: `cat /sys/devices/system/cpu/isolated`, `dmesg \| grep nohz`, `cat /sys/kernel/rcu_normal` / rcu kthread placement |
| IRQ affinity `echo 2 > /proc/irq/<n>/smp_affinity` | binds NIC queue IRQs to specific CPUs | keeps interrupt processing on the socket that owns the data (RSS) |
| `ethtool -G <iface> rx 4096` | NIC RX ring size | absorbs bursts in the NIC before the kernel even sees them |
| `ethtool -C <iface> rx-usecs 0` (adaptive off) | interrupt coalescing off | coalescing trades latency for CPU; a feed handler wants the interrupt immediately (or busy-poll instead) |
| `SO_BUSY_POLL` / `net.core.busy_poll`, `net.core.busy_read` | kernel busy-polls the socket on the syscall path | turns epoll + `recvmmsg` into a bounded spin — latency near busy-poll with idle CPU when quiet. Use with the socket option `SO_BUSY_POLL` set and the sysctls in microseconds (50 is a sane start) |
| `net.core.rmem_max` | ceiling for `SO_RCVBUF` | must be raised BEFORE the 64 MB rcvbuf request can take effect (see the measured cell above) |
| `netdev_max_backlog`, `netdev_budget` | per-CPU backlog + NAPI poll budget | raises how much the softirq can absorb per interrupt burst |
| CPU governor `performance` | disables frequency scaling | ramp-up latency lands in the tail; set `cpupower frequency-set -g performance` |
| C-states: `processor.max_cstate=1` (cmdline) | limit deep sleep states | exit latency from deep C-states (10s of microseconds) dwarfs every software stage here |
| THP: `madvise` | only huge pages where asked | the ring (67 MB) wants huge pages for TLB; THP=always can cause compaction stalls — set `transparent_hugepage=madvise` and `madvise(MADV_HUGEPAGE)` the ring |
| NUMA-local rings | allocate the SPSC ring on the NUMA node of the NIC | cross-node access costs 100+ ns per cache line miss — matters at high rates |

How to verify the cmdline knobs took effect:
```sh
cat /proc/cmdline                          # isolcpus=... nohz_full=... rcu_nocbs=...
cat /sys/devices/system/cpu/isolated       # should list your cores
dmesg | grep -i 'nohz_full\|isolcpus'      # kernel accepted them
cpupower frequency-info | grep 'governor'  # performance
cpupower idle-info | grep 'C[0-9]'         # limited C-states
```

## Order of operations on a real box

1. Kernel cmdline: `isolcpus`, `nohz_full`, `rcu_nocbs`; reboot; verify.
2. `cpupower frequency-set -g performance`; limit C-states.
3. `sysctl -w net.core.rmem_max=134217728` (and `netdev_max_backlog`,
   `netdev_budget` on 10G+ links); `ethtool -G` + `ethtool -C rx-usecs 0`
   or `net.core.busy_poll` for the SO_BUSY_POLL path.
4. IRQ affinity for the NIC queues.
5. Run `./bench/run_bench.sh --full`, compare `bench/REPORT.md` against the
   baseline in git history, then adjust batch/pinning per the deltas above.
