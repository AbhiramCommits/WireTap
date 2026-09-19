// wiretap/spsc_ring.hpp - lock-free single-producer/single-consumer ring.
//
// Contract: EXACTLY one producer thread may call try_push(); EXACTLY one
// consumer thread may call try_pop(). Calling either from multiple threads is
// undefined behavior. This is the standard discipline for hot-path queues.
//
// Design notes:
//  - Power-of-two capacity (requested capacity is rounded up); slots are
//    fixed-size and allocated once at construction. No allocation on the
//    push/pop paths, no locks, no exceptions.
//  - head and tail live on separate cache lines (alignas(64)) so producer and
//    consumer never fight over the same line. The drops counter gets its own
//    line as well.
//  - Each side caches the opposite index next to its own: the producer keeps a
//    plain (thread-private) copy of the consumer's tail, refreshed only when
//    the ring looks full; the consumer mirrors the producer's head. The common
//    path therefore touches exactly one shared cache line.
//  - Explicit acquire/release ordering (never seq_cst): the consumer's index
//    update is released against the producer's acquire load of it, and vice
//    versa, publishing slot contents along with the index.
//  - If the consumer falls behind, try_push() fails and a drop counter is
//    incremented (relaxed; read it from diagnostics code only).

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace wiretap {

template <typename T>
class SpscRing {
  static_assert(std::is_trivially_copyable<T>::value,
                "T must be trivially copyable (slots are copied by assignment)");
  static_assert(std::is_trivially_destructible<T>::value,
                "T must be trivially destructible");
  static_assert(alignof(T) <= 64, "slot alignment must not exceed 64");

  // Producer's cache line: head (shared read by consumer) plus the producer's
  // private cached copy of the consumer's tail.
  struct alignas(64) HeadLine {
    std::atomic<std::size_t> head{0};
    std::size_t tail_cache{0};
  };

  // Consumer's cache line: tail (shared read by producer) plus the consumer's
  // private cached copy of the producer's head.
  struct alignas(64) TailLine {
    std::atomic<std::size_t> tail{0};
    std::size_t head_cache{0};
  };

 public:
  // Rounds `capacity` up to the next power of two (minimum 1). Allocates the
  // slot array once; the ring never allocates again.
  explicit SpscRing(std::size_t capacity) {
    if (capacity > (std::size_t{1} << 62)) {
      throw std::length_error("SpscRing capacity too large");
    }
    capacity_ = 1;
    while (capacity_ < capacity) capacity_ <<= 1;
    mask_ = capacity_ - 1;

    void* mem = ::operator new[](capacity_ * sizeof(T), std::align_val_t{64});
    slots_ = ::new (static_cast<T*>(mem)) T[capacity_];
  }

  ~SpscRing() { ::operator delete[](slots_, std::align_val_t{64}); }

  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;

  // Producer side. Returns false (and counts a drop) if the ring is full.
  bool try_push(const T& item) noexcept {
    const std::size_t h = head_.head.load(std::memory_order_relaxed);
    if (h - head_.tail_cache == capacity_) {
      head_.tail_cache = tail_.tail.load(std::memory_order_acquire);
      if (h - head_.tail_cache == capacity_) {
        drops_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
    }
    slots_[h & mask_] = item;
    head_.head.store(h + 1, std::memory_order_release);
    return true;
  }

  // Consumer side. Returns false if the ring is empty.
  bool try_pop(T& out) noexcept {
    const std::size_t t = tail_.tail.load(std::memory_order_relaxed);
    if (t == tail_.head_cache) {
      tail_.head_cache = head_.head.load(std::memory_order_acquire);
      if (t == tail_.head_cache) return false;
    }
    out = slots_[t & mask_];
    tail_.tail.store(t + 1, std::memory_order_release);
    return true;
  }

  std::size_t capacity() const noexcept { return capacity_; }

  // Approximate occupancy (relaxed snapshot). For diagnostics only.
  std::size_t size() const noexcept {
    const std::size_t h = head_.head.load(std::memory_order_relaxed);
    const std::size_t t = tail_.tail.load(std::memory_order_relaxed);
    return h - t;
  }

  bool empty() const noexcept { return size() == 0; }
  bool full() const noexcept { return size() == capacity_; }

  // Number of pushes rejected because the ring was full. Written by the
  // producer; read it from non-hot-path code.
  std::uint64_t drops() const noexcept {
    return drops_.load(std::memory_order_relaxed);
  }

 private:
  HeadLine head_;                          // cache line 0
  TailLine tail_;                          // cache line 1
  alignas(64) std::atomic<std::uint64_t> drops_{0};  // cache line 2
  T* slots_ = nullptr;
  std::size_t capacity_ = 0;
  std::size_t mask_ = 0;
};

}  // namespace wiretap
