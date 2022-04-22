// This file was copied from
// https://github.com/parca-dev/parca-agent/blob/31253527651ebebb74c6200eb68fe9251479ed6b/parca-agent.bpf.c
// with minor refactoring.

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see
 * https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8
 * for more details
 */
#include "vmlinux.h"
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define KBUILD_MODNAME "parca-agent"

#undef container_of
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "maps.bpf.h"

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

// Max amount of different stack trace addresses to buffer in the map.
#define MAX_STACK_ADDRESSES 1024
// Max depth of each stack trace to track.
#define MAX_STACK_DEPTH 127
// Stack trace value is 1 big byte array of the stack addresses.
typedef __u64 stack_trace_type[MAX_STACK_DEPTH];

// The stack_traces map holds an array of memory addresses,
// e.g., stack_traces[1253] = [0xdeadbeef, 0x123abcde]
// where 1253 is a stack ID.
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, MAX_STACK_ADDRESSES);
  __type(key, u32);
  __type(value, stack_trace_type);
} stack_traces SEC(".maps");

struct stack_count_key_t {
  u32 pid;
  int32 user_stack_id;
  int32 kernel_stack_id;
};

// The counts map keeps track of how many times a stack trace has been seen,
// e.g., counts[{10342, 1253, 0234}] = 45 times.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct stack_count_key_t);
  __type(value, u64);
} counts SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  // Create a key for "counts" map.
  struct stack_count_key_t key = {.pid = tgid};
  // Read user-space stack ID and insert memory addresses into stack_traces map.
  // The positive or null stack id is returned on success,
  // or a negative error in case of failure.
  key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
  // Read kernel-space stack ID and insert memory addresses into stack_traces map.
  key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

  u64 zero = 0;
  u64 *seen;
  seen = bpf_map_lookup_or_try_init(&counts, &key, &zero);
  if (!seen)
    return 0;
  // Atomically increments the seen counter.
  __sync_fetch_and_add(seen, 1);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
