#!/bin/sh

# We would like to `allow` individual lints after setting an entire group of
# them to `warn`. This cannot be done using the CLI in stable Rust. Until the
# fix for this is stabilized, any overrides must be specified as attributes.
# See the following for more information:
# - https://github.com/rust-lang/rust-clippy/issues/4778
# - https://github.com/rust-lang/rust/issues/58211
# - https://github.com/rust-lang/rust/pull/67885

exec cargo clippy                                 \
    --profile test                                \
    --                                            \
    --warn absolute_paths_not_starting_with_crate \
    --warn deprecated_in_future                   \
    --warn macro_use_extern_crate                 \
    --warn trivial_casts                          \
    --warn trivial_numeric_casts                  \
    --warn unsafe_code                            \
    --warn unused_labels                          \
    --warn unused_lifetimes                       \
    --warn unused_qualifications                  \
    --warn clippy::nursery                        \
    --warn clippy::pedantic                       \
    --warn clippy::clone_on_ref_ptr               \
    --warn clippy::dbg_macro                      \
    --warn clippy::decimal_literal_representation \
    --warn clippy::float_arithmetic               \
    --warn clippy::float_cmp_const                \
    --warn clippy::get_unwrap                     \
    --warn clippy::mem_forget                     \
    --warn clippy::multiple_inherent_impl         \
    --warn clippy::option_unwrap_used             \
    --warn clippy::print_stdout                   \
    --warn clippy::result_unwrap_used             \
    --warn clippy::string_add                     \
    --warn clippy::unimplemented                  \
    --warn clippy::use_debug                      \
    --warn clippy::wrong_pub_self_convention      \
    --deny warnings
