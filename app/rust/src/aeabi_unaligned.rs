//! Unaligned memory access helpers of the ARM run-time ABI.
//!
//! The Rust library is built for `thumbv6m-none-eabi` on all devices: like
//! the C SDK (`-mno-unaligned-access`), it never accesses memory unaligned.
//! Since LLVM 23 (from nightly-2026-09-15), the ARM backend lowers unaligned
//! 4- and 8-byte loads and stores of such targets to calls to
//! `__aeabi_uread4`, `__aeabi_uwrite4`, `__aeabi_uread8` and
//! `__aeabi_uwrite8` when optimizing for size (`opt-level = "z"`).
//! `compiler_builtins` does not provide them for `thumbv6m-none-eabi` in that
//! nightly, so the link fails without these definitions.
//!
//! They are written in Thumb-1 assembly, which runs on every device, so that
//! the compiler cannot turn the byte accesses back into a call to themselves,
//! and defined weak so that another definition (e.g. a future
//! `compiler_builtins`) takes precedence. Same code as
//! `ledger_device_sdk/src/aeabi_unaligned.rs` of the Rust SDK.

core::arch::global_asm!(
    ".syntax unified",
    ".thumb",
    // int __aeabi_uread4(void *address)
    ".section .text.__aeabi_uread4,\"ax\",%progbits",
    ".weak __aeabi_uread4",
    ".type __aeabi_uread4,%function",
    ".thumb_func",
    "__aeabi_uread4:",
    "ldrb r1, [r0, #0]",
    "ldrb r2, [r0, #1]",
    "lsls r2, r2, #8",
    "orrs r1, r2",
    "ldrb r2, [r0, #2]",
    "lsls r2, r2, #16",
    "orrs r1, r2",
    "ldrb r2, [r0, #3]",
    "lsls r2, r2, #24",
    "orrs r1, r2",
    "movs r0, r1",
    "bx lr",
    ".size __aeabi_uread4, . - __aeabi_uread4",
    // int __aeabi_uwrite4(int value, void *address), returns value
    ".section .text.__aeabi_uwrite4,\"ax\",%progbits",
    ".weak __aeabi_uwrite4",
    ".type __aeabi_uwrite4,%function",
    ".thumb_func",
    "__aeabi_uwrite4:",
    "strb r0, [r1, #0]",
    "lsrs r2, r0, #8",
    "strb r2, [r1, #1]",
    "lsrs r2, r0, #16",
    "strb r2, [r1, #2]",
    "lsrs r2, r0, #24",
    "strb r2, [r1, #3]",
    "bx lr",
    ".size __aeabi_uwrite4, . - __aeabi_uwrite4",
    // long long __aeabi_uread8(void *address): low word in r0, high in r1
    ".section .text.__aeabi_uread8,\"ax\",%progbits",
    ".weak __aeabi_uread8",
    ".type __aeabi_uread8,%function",
    ".thumb_func",
    "__aeabi_uread8:",
    "mov r3, r0",
    "ldrb r1, [r3, #4]",
    "ldrb r2, [r3, #5]",
    "lsls r2, r2, #8",
    "orrs r1, r2",
    "ldrb r2, [r3, #6]",
    "lsls r2, r2, #16",
    "orrs r1, r2",
    "ldrb r2, [r3, #7]",
    "lsls r2, r2, #24",
    "orrs r1, r2",
    "ldrb r0, [r3, #0]",
    "ldrb r2, [r3, #1]",
    "lsls r2, r2, #8",
    "orrs r0, r2",
    "ldrb r2, [r3, #2]",
    "lsls r2, r2, #16",
    "orrs r0, r2",
    "ldrb r2, [r3, #3]",
    "lsls r2, r2, #24",
    "orrs r0, r2",
    "bx lr",
    ".size __aeabi_uread8, . - __aeabi_uread8",
    // long long __aeabi_uwrite8(long long value, void *address), returns value
    ".section .text.__aeabi_uwrite8,\"ax\",%progbits",
    ".weak __aeabi_uwrite8",
    ".type __aeabi_uwrite8,%function",
    ".thumb_func",
    "__aeabi_uwrite8:",
    "strb r0, [r2, #0]",
    "lsrs r3, r0, #8",
    "strb r3, [r2, #1]",
    "lsrs r3, r0, #16",
    "strb r3, [r2, #2]",
    "lsrs r3, r0, #24",
    "strb r3, [r2, #3]",
    "strb r1, [r2, #4]",
    "lsrs r3, r1, #8",
    "strb r3, [r2, #5]",
    "lsrs r3, r1, #16",
    "strb r3, [r2, #6]",
    "lsrs r3, r1, #24",
    "strb r3, [r2, #7]",
    "bx lr",
    ".size __aeabi_uwrite8, . - __aeabi_uwrite8",
    ".text",
);
