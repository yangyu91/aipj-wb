# Capability Checklist

Use this checklist to avoid missing common reverse-engineering skills.

## Universal skills
- Evidence preservation, hashing, chain-of-custody notes
- File identification, entropy, metadata, signatures, timestamps
- Strings extraction: ASCII, UTF-16LE, high-entropy config blobs, URLs, paths, registry keys, mutexes, user agents, error messages
- Symbol/import/export/resource analysis
- Control-flow and data-flow mapping
- Hypothesis tracking and confidence scoring
- Report writing with reproducible evidence

## Native binaries
- PE/ELF/Mach-O headers, sections/segments, relocations, symbols
- Architecture and ABI identification: x86/x64/ARM/MIPS/RISC-V
- Compiler/runtime fingerprints: MSVC, GCC/Clang, Go, Rust, Delphi, Nim
- Disassembly/decompilation navigation, xrefs, call graph, vtables, RTTI
- Debugging, tracing, memory maps, breakpoints/watchpoints
- Packers/obfuscators: entropy, import resolution, unpacking strategy, anti-debug indicators
- Android native ELF/SO specifics: JNI export/RegisterNatives, init/init_array/fini, dynamic linker behavior, TracerPid/ptrace anti-debug, timing traps
- Linux kernel module (LKM) reversing: ioctl command dispatch, copy_from_user/copy_to_user structures, syscall table hijacking (sys_call_table), kprobes/ftrace hooks, netfilter hooks
- Kernel environment evidence: /proc/modules load addresses, kernel version/fingerprint (GKI/vendor), sepolicy/selinux context, KASLR state

## Managed and script runtimes
- .NET metadata, IL, assemblies, resources, deobfuscation indicators
- JVM bytecode, Android DEX/APK, manifests, permissions, native libraries
- Python/Node/PowerShell/Lua scripts, packed bytecode, dependency manifests

## Firmware and embedded
- Container extraction, filesystem carving, bootloader/kernel/rootfs layout
- CPU/SoC identification, endianness, memory maps
- Init scripts, services, web endpoints, hardcoded credentials, update mechanism
- Emulation or targeted static review when execution is impractical

## Mobile
- APK/IPA structure, manifests/entitlements, permissions, URL schemes
- Network endpoints, certificate pinning indicators, local storage, secrets
- Native bridges and JNI/Swift/Obj-C boundaries

## Documents and parsers
- File format validation, embedded objects/macros/scripts
- Parser attack surface, decompression/archive nesting, malformed field handling
- Safe sandboxing and metadata extraction before opening in GUI tools

## Web penetration testing
- Passive reconnaissance: DNS, headers, TLS/SSL, robots.txt, sitemap.xml
- Technology fingerprinting: server, framework, CMS, language, frontend libraries
- CVE auto-matching: version identification and NVD/local database querying
- Active testing: directory/file bruteforcing, parameter discovery, SQL injection, XSS, authentication brute-force
- API security: endpoint enumeration, REST/GraphQL/SOAP analysis, authz/authn testing

## Network protocol reversing
- Traffic capture: tcpdump, Wireshark, mitmproxy
- Protocol analysis: message framing, delimiters, endianness, serialization (Protobuf, JSON, Binary)
- State machine recovery: INIT, AUTH, READY, DISCONNECT transitions
- Vulnerability testing: replay attacks, session hijacking, downgrade attacks, crypto weaknesses
- Man-in-the-middle: certificate pinning bypass, traffic interception and modification

## Vulnerability-focused skills
- Input surface mapping
- Trust-boundary identification
- Bounds, integer, lifetime, format-string, injection, deserialization, authz/authn, crypto misuse, insecure update/storage checks
- Crash triage and root cause
- Patch diffing and regression tests
- Severity, remediation, and disclosure-ready reporting
