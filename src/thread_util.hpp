// wiretap/thread_util.hpp - CPU affinity, SCHED_FIFO, thread naming.
//
// All functions apply to the CALLING thread (use them at the top of a thread
// function). They are cold-path helpers: failure is reported once to stderr
// and never aborts the thread.

#pragma once

#include <pthread.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <sched.h>
#endif

namespace wiretap {

// Pins the calling thread to one CPU. Returns false (and prints a warning)
// when affinity is unavailable (EPERM or non-Linux platforms).
inline bool pin_cpu(int cpu) noexcept {
  if (cpu < 0)
    return false;
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (::pthread_setaffinity_np(::pthread_self(), sizeof(set), &set) == 0) {
    return true;
  }
  std::fprintf(stderr, "wiretap: pin to CPU %d failed: %s\n", cpu, std::strerror(errno));
#else
  (void)cpu;
  std::fprintf(stderr, "wiretap: CPU affinity is not supported on this platform\n");
#endif
  return false;
}

// Moves the calling thread to SCHED_FIFO. Prints a clear warning when denied:
// real-time scheduling needs CAP_SYS_NICE (or root).
inline bool set_fifo(int priority, const char* role) noexcept {
  (void)priority;
  (void)role;
#if defined(__linux__)
  struct sched_param param {};
  param.sched_priority = priority;
  if (::pthread_setschedparam(::pthread_self(), SCHED_FIFO, &param) == 0) {
    return true;
  }
  std::fprintf(stderr,
               "wiretap: %s thread: SCHED_FIFO(prio %d) denied: %s. "
               "Continuing with SCHED_OTHER. To enable real-time scheduling, "
               "grant CAP_SYS_NICE (e.g. `sudo setcap cap_sys_nice+ep "
               "$(which wiretap_recv)`) or run as root.\n",
               role, priority, std::strerror(errno));
#else
  std::fprintf(stderr,
               "wiretap: %s thread: SCHED_FIFO is not supported on this "
               "platform; continuing with the default policy.\n",
               role);
#endif
  return false;
}

inline void set_current_thread_name(const char* name) noexcept {
#if defined(__linux__)
  ::pthread_setname_np(::pthread_self(), name);
#elif defined(__APPLE__)
  ::pthread_setname_np(name);
#else
  (void)name;
#endif
}

}  // namespace wiretap
