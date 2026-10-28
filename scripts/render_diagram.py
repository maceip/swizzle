#!/usr/bin/env python3
# Renders the Swizzle 3-Tier architecture with 24-bit ANSI orange-to-red gradient borders
import html
import pathlib
import sys

DIAGRAM = """\
┌────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: AST & Superset Cohort Builder (Cadence: 1h – 6h, Background Build Pool)    │
│  [Kernel Source] ──► Cacheline-Bucketed RANDSTRUCT (Seed_C, 64B cacheline bounds)  │
│                  ──► Pinned eBPF Manifest (noinline, retain) + Frozen VDSO / UAPI  │
│                  ──► LLVM RegAlloc Jitter (-rng-seed=Seed_C) + -ffunction-sections │
│                  ──► Emits Indexed Thin Superset Archive (vmlinux-superset.a)      │
└─────────────────────────────────────────┬──────────────────────────────────────────┘
                                          │
                                          ▼ (Cached in Cohort Artifact Store)
┌────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: Hardware-Profile Linker & UKI Sealer (Cadence: Per Cohort × Host Profile)  │
│  [Superset .a]   ──► Modalias Profile Slicer + ld.lld --gc-sections --emit-relocs  │
│                  ──► Cohort .BTF Synthesis (pahole -J) + Two-Pass kallsyms         │
│                  ──► swizzle-pack-relocs.py (Packs SHT_RELA -> .init.swizzle_relocs│
│                  ──► Offline UKI Signing + SEV-SNP ID_BLOCK / TDX CoRIM / pcrlock  │
└─────────────────────────────────────────┬──────────────────────────────────────────┘
                                          │
                                          ▼ (Static Golden Hash Measured by Hardware)
┌────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 3: In-Enclave Early-Boot Self-Relinker (libswizzle_boot.a, Every Boot, ~45ms) │
│  [Cohort UKI]    ──► Verified Boot Finalizes Static PCR[4] / RTMR[1] / SNP Launch  │
│                  ──► Draws 256-bit Hardware Seed (RDSEED) Inside CPU Package       │
│                  ──► Staged Scratch Permutation (.text*, .data*, .rodata* + 0xcc)  │
│                  ──► In-Place Heapsort (__ex_table, .orc_unwind_ip, kallsyms_idx)  │
│                  ──► RFC 9180 HPKE Seed Sealer + memzero_explicit() ──► Boot OS    │
└───────────────────┬──────────────────────────────────────────────┬─────────────────┘
                    │                                              │
                    ▼ (In-Enclave Runtime)                         ▼ (Zero-Storage)
┌──────────────────────────────────────┐      ┌──────────────────────────────────────┐
│ Hardened Target Node / CVM           │      │ Symbol & Attestation Vault           │
│ - Redacted kallsyms (func+0xoff/sz)  │      │ - Signer-Delegated Root Verification │
│ - SipHash %px/%pK & Locked /proc     │      │ - Unseals Panic hpke:v1:<enc>:<ct>   │
│ - Per-Boot RANDOM_KMALLOC_CACHES     │      │ - Replays Seed_B -> Canonical DWARF  │
│ - Intact eBPF CO-RE & CRIU VDSO      │      │ - Zero Per-Boot Binary Storage       │
└──────────────────────────────────────┘      └──────────────────────────────────────┘"""

BORDER_CHARS = set("┌─┐│└┘┬┴├┤►▼")
RESET = "\033[0m"
TEXT_COLOR = "\033[38;2;230;235;240m"

lines = DIAGRAM.splitlines()
total_rows = max(len(lines) - 1, 1)
max_cols = max(len(line) for line in lines)


def render_ansi() -> None:
    for r, line in enumerate(lines):
        out = []
        for c, ch in enumerate(line):
            if ch in BORDER_CHARS:
                # Diagonal blend: 70% vertical progression + 30% horizontal progression
                t = (0.70 * (r / total_rows)) + (0.30 * (c / max_cols))
                # Interpolate #FF9E00 (255, 158, 0) -> #D90429 (217, 4, 41)
                red = int(255 - t * (255 - 217))
                green = int(158 - t * (158 - 4))
                blue = int(0 + t * 41)
                out.append(f"\033[38;2;{red};{green};{blue}m{ch}{RESET}")
            else:
                out.append(f"{TEXT_COLOR}{ch}{RESET}")
        print("".join(out))


def render_svg(out_path: pathlib.Path) -> None:
    char_w = 8.4
    line_h = 19.0
    pad_x = 24.0
    pad_y = 28.0
    width = int(pad_x * 2 + max_cols * char_w)
    height = int(pad_y * 2 + len(lines) * line_h)

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">',
        '  <rect width="100%" height="100%" rx="10" ry="10" fill="#0d1117"/>',
        '  <g font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="14" xml:space="preserve">',
    ]

    for r, line in enumerate(lines):
        y = pad_y + (r + 0.8) * line_h
        spans = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch in BORDER_CHARS:
                t = (0.70 * (r / total_rows)) + (0.30 * (i / max_cols))
                red = int(255 - t * (255 - 217))
                green = int(158 - t * (158 - 4))
                blue = int(0 + t * 41)
                color = f"#{red:02x}{green:02x}{blue:02x}"
                spans.append(f'<tspan fill="{color}">{html.escape(ch)}</tspan>')
                i += 1
            else:
                start = i
                while i < n and line[i] not in BORDER_CHARS:
                    i += 1
                chunk = html.escape(line[start:i])
                spans.append(f'<tspan fill="#e6ebf0">{chunk}</tspan>')
        svg.append(f'    <text x="{pad_x}" y="{y:.1f}">{"".join(spans)}</text>')

    svg.append("  </g>")
    svg.append("</svg>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(svg) + "\n", encoding="utf-8")


if __name__ == "__main__":
    render_ansi()
    if "--svg" in sys.argv:
        idx = sys.argv.index("--svg")
        target = pathlib.Path(sys.argv[idx + 1])
        render_svg(target)
