# Reverse Techniques

## Static-first triage
1. Identify container/file type and architecture.
2. Map sections/segments/resources and note anomalies.
3. Extract strings and categorize: config, network, file paths, commands, errors, crypto/API names.
4. Inspect imports/exports/symbols to infer capabilities.
5. Identify entry points and high-signal functions by xrefs from strings/imports.
6. Build a hypothesis table: evidence, explanation, confidence, validation step.

## Decompilation workflow
- Rename functions and variables based on evidence, not guesses.
- Use comments for invariants, input constraints, and side effects.
- Build call graph slices around input parsing, decoding, authentication, update, crypto, file/network boundaries.
- Convert key logic into pseudocode only as much as needed for the report.
- Validate decompiler output against disassembly for tricky pointer arithmetic, signedness, switch tables, and optimized code.

## Dynamic workflow
- Use snapshots and isolated labs.
- Start with passive observation: process/file/registry/network traces.
- Add debugger breakpoints on high-signal APIs or functions discovered statically.
- Capture minimal reproduction steps and logs.
- Compare runtime behavior with static hypotheses.

## Packed or obfuscated artifacts
- Look for high entropy, unusual sections, sparse imports, runtime import resolution, anti-debug checks, self-modifying code, or loader stubs.
- Prefer safe unpacking in a lab snapshot; preserve pre/post-unpack hashes and memory dumps.
- If unpacking is not feasible, focus on loader behavior, configuration extraction, and observable I/O.

## Patch diffing
- Align old/new versions by symbols, strings, functions, and CFG similarity.
- Identify changed input validation, bounds checks, authz checks, crypto/storage behavior, and parser state machines.
- Treat patched code as a clue, then independently validate root cause and affected surface.

## Protocol/config/file-format recovery
- Collect magic constants, length fields, checksums, compression/encryption markers, state transitions, and error strings.
- Map parser functions and validation branches.
- Produce a field table: offset/name/type/constraints/evidence/function.

## Mobile notes
- Inspect manifest/permissions/entitlements before runtime work.
- Map network endpoints, local storage, IPC, deep links, exported components, JNI/native boundaries.
- Treat secrets in resources/config as findings only after confirming exposure and impact.

## Android kernel module reversing

1. Identify kernel module:
   - List loaded modules: `cat /proc/modules` or `lsmod`.
   - Extract `.ko` file from `/vendor/lib/modules/` or `/system/lib/modules/`.
   - Record kernel version: `uname -r` (GKI or vendor-specific).
2. Static analysis of `.ko`:
   - Load in Ghidra/IDA with kernel-specific architecture (ARM64/ARM).
   - Identify `module_init` and `module_exit` entry points.
   - Map `file_operations` structure: `.open`, `.release`, `.unlocked_ioctl`, `.compat_ioctl`.
   - Extract ioctl command codes and their associated handler functions.
3. Data structure recovery:
   - Analyze `copy_from_user` and `copy_to_user` calls to recover user-kernel buffer layouts.
   - Document `ioctl` input/output structures: offset, field name, type, constraints.
4. Syscall hook detection:
   - Look for `sys_call_table` modifications (direct writes or via kprobes/ftrace).
   - Identify netfilter hooks for packet manipulation.
   - Detect inline hooking via function prologue overwrites.
5. Environment evidence:
   - Record SELinux context: `getenforce`, `ls -Z`.
   - Check KASLR status: `cat /proc/cmdline` for `kaslr` flag.
   - Document module load address from `/proc/modules`.
6. Safe local testing:
   - Use rooted test device/emulator with unlocked bootloader.
   - Load module only in lab: `insmod /path/to/module.ko`.
   - Validate ioctl commands with custom userspace tester.
   - Unload after testing: `rmmod module_name`.

## Firmware notes
- Extract filesystem and identify init/service startup.
- Prioritize web/admin interfaces, update handlers, network daemons, scripts, and hardcoded credentials.
- If emulation is hard, use static analysis plus selective chroot/qemu-user execution for individual binaries when safe.
