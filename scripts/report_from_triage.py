#!/usr/bin/env python3
"""Build an initial aipj report from triage JSON files."""
from __future__ import annotations

import argparse
import glob
import json
from datetime import datetime, timezone
from pathlib import Path


def risk_hint(item: dict) -> tuple[str, list[str]]:
    reasons: list[str] = []
    entropy = item.get("prefix_entropy", 0)
    indicators = item.get("indicators", {})
    magic = ", ".join(item.get("magic_hints", []))
    profiles = item.get("profiles", [])

    # Generic risk indicators
    if entropy >= 7.2:
        reasons.append("high prefix entropy suggests compression, encryption, packing, or dense binary data")
    if indicators.get("urls") or indicators.get("ipv4"):
        reasons.append("network indicators present")
    if indicators.get("suspicious_terms"):
        reasons.append("high-signal API/command strings present")
    if any(x in magic.lower() for x in ["executable", "elf", "mach-o", "dex", "apk"]):
        reasons.append("executable or bytecode artifact")

    # ========== ANDROID KERNEL SPECIFIC ==========
    # Detect kernel module indicators
    if ".ko" in item.get("name", "").lower() or "kernel module" in magic.lower():
        reasons.append("kernel module (.ko) detected — ioctl/syscall hook analysis required")
    if "ioctl" in str(indicators.get("strings", [])):
        reasons.append("ioctl command codes present — permission/privilege escalation review needed")
    if "sys_call_table" in str(indicators.get("strings", [])):
        reasons.append("syscall table manipulation detected — kernel stability risk")
    if "copy_from_user" in str(indicators.get("strings", [])):
        reasons.append("copy_from_user/copy_to_user patterns present — recover user-kernel buffer layouts")
    if "magisk" in str(indicators.get("strings", [])) or "sepolicy" in str(indicators.get("strings", [])):
        reasons.append("root/hiding mechanisms (Magisk/sepolicy) detected")

    # Severity escalation
    if len(reasons) >= 4:
        return "Medium/High", reasons
    if len(reasons) >= 2:
        return "Medium", reasons
    if reasons:
        return "Low/Medium", reasons
    return "Unknown/Low", ["limited evidence from offline triage"]


def generate_specialized_next_steps(profiles: list[str], indicators: dict) -> list[str]:
    """Generate context-aware next-step menu based on detected profiles."""
    steps = []
    base_idx = 1

    # Generic steps
    steps.append("Continue static reverse engineering of high-signal strings, imports, entry points")
    steps.append("Run `tool_audit.py --profile <profile>` to check the local sandbox toolchain before deeper work")

    # Android kernel-specific steps
    if "android-kernel" in profiles or ".ko" in str(indicators.get("strings", [])):
        steps.append("Extract ioctl command codes and map file_operations structure")
        steps.append("Analyze syscall table hijacking and kprobes/ftrace hooks")
        steps.append("Document kernel version, KASLR status, and SELinux context")
        steps.append("Design safe local test harness for .ko module validation")

    # Web pentest specific steps
    if "web" in profiles or any(x in str(indicators).lower() for x in ["login", "admin", "sql", "xss", "wordpress", "django"]):
        steps.append("Run automated web penetration test: python auto_pentest.py --target <url> --out <report>")
        steps.append("Perform technology stack fingerprinting and CVE matching")
        steps.append("Conduct directory bruteforce and admin panel discovery")
        steps.append("Test for SQL injection using boolean-based blind techniques")
        steps.append("Scan for XSS vulnerabilities using dalfox or manual payloads")
        steps.append("Generate comprehensive web penetration test report")

    # Network reversing specific steps
    if "network" in profiles or any(x in str(indicators).lower() for x in ["tcp", "udp", "http", "pcap", "wireshark"]):
        steps.append("Capture and analyze network traffic using Wireshark/tcpdump")
        steps.append("Recover protocol structure, message formats, and state machines")
        steps.append("Identify encryption/serialization mechanisms (Protobuf, TLS, custom)")
        steps.append("Test for authentication bypass and replay vulnerabilities")
        steps.append("Produce protocol reverse engineering report")

    # Generic fallback
    if not steps:
        steps.append("Build a function/module map and identify trust boundaries")
        steps.append("If the user selects dynamic work, run tracing only inside an isolated lab snapshot")
        steps.append("Perform vulnerability-focused review of parser, update, authentication, and unsafe memory paths")

    # Add final optional steps
    steps.append("Produce a deep reverse report or vulnerability advisory from validated evidence")

    return steps


def main() -> int:
    parser = argparse.ArgumentParser(description="Create initial Markdown report from triage JSON")
    parser.add_argument("inputs", nargs="+", help="Triage JSON files or glob patterns")
    parser.add_argument("--out", required=True, help="Output Markdown report")
    parser.add_argument("--title", default="Reverse Engineering Initial Report")
    parser.add_argument("--target-type", default="generic", choices=["generic", "android-kernel", "network", "web"],
                        help="Target type for specialized report sections")
    args = parser.parse_args()

    paths: list[Path] = []
    for p in args.inputs:
        matches = glob.glob(p)
        paths.extend(Path(m).resolve() for m in matches) if matches else paths.append(Path(p).resolve())
    items = [json.loads(p.read_text(encoding="utf-8")) for p in paths]

    # Collect all profiles and indicators for next-step generation
    all_profiles: list[str] = []
    all_indicators: dict = {"strings": []}
    for item in items:
        all_profiles.extend(item.get("profiles", []))
        if ".ko" in item.get("name", "").lower():
            all_profiles.append("android-kernel")
    all_profiles = list(dict.fromkeys(all_profiles))

    lines = [
        f"# {args.title}",
        "",
        f"- Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "- Current phase: Analysis → Initial report",
        "- Method: Offline triage; artifacts were not executed.",
        f"- Target type: {args.target_type}",
        "",
        "## Artifact inventory",
        "| Name | Size | SHA-256 | Type hints | Profiles | Entropy | Risk hint |",
        "|---|---:|---|---|---|---:|---|",
    ]
    finding_id = 1
    finding_lines: list[str] = []
    for item in items:
        risk, reasons = risk_hint(item)
        profiles = ", ".join(item.get("profiles", []))
        magic = ", ".join(item.get("magic_hints", []))
        entropy = item.get("prefix_entropy", 0)
        lines.append(f"| {item.get('name','')} | {item.get('size',0)} | `{item['hashes']['sha256']}` | {magic} | {profiles} | {entropy:.3f} | {risk} |")
        finding_lines += [
            f"### F{finding_id}: {item.get('name','artifact')} triage observations",
            f"- Path: `{item.get('path','')}`",
            f"- Evidence: magic={magic}; entropy={entropy:.3f}; sha256={item['hashes']['sha256']}",
            f"- Interpretation: {'; '.join(reasons)}.",
            f"- Confidence: Medium for file facts; Low/Medium for behavior until reverse/dynamic validation.",
            "",
        ]
        finding_id += 1

    lines += ["", "## Verified facts", ""] + finding_lines

    # ========== SPECIALIZED SECTIONS ==========
    if args.target_type == "android-kernel" or "android-kernel" in all_profiles:
        lines += [
            "",
            "## Android Kernel Module Specialized Section",
            "",
            "### Required Evidence (to be filled during analysis)",
            "- Kernel version: ________",
            "- .ko load address (from /proc/modules): ________",
            "- ioctl command codes: ________ (list with hex values)",
            "- SELinux context: ________",
            "- KASLR status: ________",
            "",
            "### Recommendations",
            "- Use Ghidra/radare2 for .ko static analysis",
            "- Extract ioctl command codes and file_operations structure",
            "- Test only on rooted device/emulator with unlocked bootloader",
            "",
        ]

    if args.target_type == "web" or "web" in all_profiles:
        lines += [
            "",
            "## Web Penetration Testing Specialized Section",
            "",
            "### Target Details",
            "- URL: ________",
            "- Authorization: [ ] Whitelisted by user",
            "- Tech Stack: ________",
            "",
            "### Recommendations",
            "- Run automated pentest: `python auto_pentest.py --target <url> --out <report>`",
            "- Check for common admin paths and directory listing",
            "- Test for SQLi and XSS on identified endpoints",
            "",
        ]

    if args.target_type == "network" or "network" in all_profiles:
        lines += [
            "",
            "## Network Protocol Reversing Specialized Section",
            "",
            "### Traffic Details",
            "- Protocol: TCP / UDP / HTTP / Other: ________",
            "- PCAP Path: ________",
            "- Endpoints: ________",
            "",
            "### Recommendations",
            "- Use Wireshark to identify message framing and delimiters",
            "- Extract serialization patterns (JSON, Protobuf, Binary)",
            "- Map state transitions and session handling",
            "",
        ]

    # ========== INDICATOR SUMMARY ==========
    lines += [
        "## Indicator summary",
        "",
    ]
    for item in items:
        lines.append(f"### {item.get('name','artifact')}")
        inds = item.get("indicators", {})
        if not inds:
            lines.append("- No high-signal indicators found in extracted strings.")
        for name, vals in inds.items():
            preview = ", ".join(f"`{v}`" for v in vals[:10])
            lines.append(f"- {name}: {preview}")
        lines.append("")

    # ========== TOOL RECOMMENDATIONS ==========
    lines += ["## Local tool recommendations", ""]
    all_tools = []
    for item in items:
        all_tools.extend(item.get("recommended_tools", []))
    all_tools = list(dict.fromkeys(all_tools))
    lines.append(f"- Suggested profiles: {', '.join(all_profiles) if all_profiles else 'generic'}")
    if all_tools:
        for tool in all_tools:
            lines.append(f"- {tool}")
    else:
        lines.append("- No specific tool recommendation yet.")
    lines.append("")

    # ========== NEXT STEPS (context-aware) ==========
    next_steps = generate_specialized_next_steps(all_profiles, all_indicators)
    lines += ["## Recommended next steps", ""]
    for idx, step in enumerate(next_steps, 1):
        lines.append(f"{idx}. {step}")
    lines.append("")

    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())