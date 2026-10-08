// SPDX-License-Identifier: Apache-2.0
//! mimalloc's one setting that matters here.
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

/// Turn off eager arena commit unless the operator chose a value. Call it first in `main`.
#[cfg(not(any(miri, zion_tsan)))]
pub fn tune() {
    if std::env::var_os("MIMALLOC_ARENA_EAGER_COMMIT").is_some() {
        return;
    }
    // SAFETY: `mi_option_set` stores an integer in mimalloc's option table; it takes no
    // pointer and may be called at any time (it applies to arenas reserved afterwards).
    unsafe { mi_option_set(MI_OPTION_ARENA_EAGER_COMMIT, 0) };
}

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
