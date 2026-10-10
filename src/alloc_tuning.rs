// SPDX-License-Identifier: Apache-2.0
//! mimalloc's two settings that matter here: both keep the process's memory near what the
//! response cache counts.
//!
//! mimalloc reserves a 1 GiB arena and, on Linux, commits it eagerly (`arena_eager_commit =
//! 2`: "on systems that overcommit"). Measured on the response cache (#590) with no budget,
//! 200 MiB of cached bodies grew the process by 360 to 440 MiB under that default and by
//! 220 MiB with `MIMALLOC_ARENA_EAGER_COMMIT=0` (1.1 times what `zion_cache_bytes` counts;
//! glibc's malloc: the same), for bodies of 64 KiB, 300 KiB and 1 MiB alike. `[server]
//! cache_max_memory_mb` is a budget on what the cache counts, so a process that holds twice
//! that makes the budget a lie. Eager commit is a start-up speed trade that this proxy does
//! not need.
//!
//! The environment variable `MIMALLOC_ARENA_EAGER_COMMIT` is still honoured: it is read
//! first, and an operator who set it keeps their value.
//!
//! The second is transparent huge pages. Where `/sys/kernel/mm/transparent_hugepage/enabled`
//! is `always`, the kernel backs mimalloc's arena with 2 MiB pages and a page touched brings
//! in two megabytes. Measured on such machines (#657), 150 MiB of cached 1 MiB bodies: the
//! process grew by 200 to 260 MiB in a release build, and by 330 to 360 on two of them (1.3
//! to 2.4 times what the cache counts, steadily: how much depends on the huge pages the
//! machine has to give), and by 161 to 171 MiB with huge pages off for the process; 200 MiB
//! cached held 38 to 68 MiB in huge pages. CPU per request did not move, for a 5 KB cached
//! document (34.9 against 34.8 µs, eight alternated runs) or for a cached megabyte (843
//! against 818 µs). So
//! zion turns them off for its own process (`prctl(PR_SET_THP_DISABLE)`: this process and the
//! ones it would start, nothing system-wide). Where the setting is `madvise` nothing changes:
//! mimalloc never asked for them.
//!
//! `MIMALLOC_ALLOW_THP` is mimalloc's variable for the same thing and is honoured the same
//! way: set to anything, zion leaves the matter to mimalloc (`1` keeps huge pages, `0` makes
//! mimalloc turn them off itself). The crate's `no_thp` feature is not the switch: built with
//! it, the process still starts with huge pages allowed.

// The two option functions of the mimalloc library the binary already links (the `mimalloc`
// crate builds it). Declared here because the bindings expose them only behind a feature that
// pulls in another crate, for two functions.
#[cfg(not(any(miri, zion_tsan)))]
extern "C" {
    fn mi_option_set(option: std::ffi::c_int, value: std::ffi::c_long);
    #[cfg(test)]
    fn mi_option_get(option: std::ffi::c_int) -> std::ffi::c_long;
}

/// `mi_option_arena_eager_commit`: the same index in the vendored mimalloc v2 and v3 headers
/// (after show_errors, show_stats, verbose and eager_commit); the bindings do not name it.
#[cfg(not(any(miri, zion_tsan)))]
const MI_OPTION_ARENA_EAGER_COMMIT: std::ffi::c_int = 4;

/// Turn off eager arena commit and transparent huge pages, each unless the operator chose a
/// value. Call it first in `main`.
#[cfg(not(any(miri, zion_tsan)))]
pub fn tune() {
    thp_off();
    if std::env::var_os("MIMALLOC_ARENA_EAGER_COMMIT").is_some() {
        return;
    }
    // SAFETY: `mi_option_set` stores an integer in mimalloc's option table; it takes no
    // pointer and may be called at any time (it applies to arenas reserved afterwards).
    unsafe { mi_option_set(MI_OPTION_ARENA_EAGER_COMMIT, 0) };
}

/// Transparent huge pages off for this process, unless `MIMALLOC_ALLOW_THP` is set.
#[cfg(all(target_os = "linux", not(any(miri, zion_tsan))))]
fn thp_off() {
    if std::env::var_os("MIMALLOC_ALLOW_THP").is_some() {
        return;
    }
    // SAFETY: `prctl` with an integer option and integer arguments: it sets a flag on this
    // process's address space and touches no memory of ours. A kernel without the option
    // returns an error, which changes nothing.
    unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) };
}

#[cfg(all(not(target_os = "linux"), not(any(miri, zion_tsan))))]
fn thp_off() {}

#[cfg(any(miri, zion_tsan))]
pub fn tune() {}

#[cfg(all(test, not(any(miri, zion_tsan))))]
mod tests {
    /// The index above is a bare number: if a mimalloc update reorders its options it names
    /// something else. The option's documented default is 2, and 0 after `tune`.
    #[test]
    fn the_option_index_still_names_arena_eager_commit() {
        use super::{mi_option_get, mi_option_set};
        let before = unsafe { mi_option_get(super::MI_OPTION_ARENA_EAGER_COMMIT) };
        // Only the environment can have moved it from the documented default.
        if std::env::var_os("MIMALLOC_ARENA_EAGER_COMMIT").is_none() {
            assert!(
                before == 2 || before == 0,
                "option 4 reads {before}: not arena_eager_commit's default of 2"
            );
        }
        unsafe { mi_option_set(super::MI_OPTION_ARENA_EAGER_COMMIT, 0) };
        assert_eq!(
            unsafe { mi_option_get(super::MI_OPTION_ARENA_EAGER_COMMIT) },
            0
        );
        unsafe { mi_option_set(super::MI_OPTION_ARENA_EAGER_COMMIT, before) };
    }
}
