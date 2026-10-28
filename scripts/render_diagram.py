#!/usr/bin/env python3
# Renders the Swizzle 3-Tier architecture with 24-bit ANSI orange-to-red gradient borders
import html
import pathlib
import sys

DIAGRAM = """\
┌───────────────────────────────────────────────────────────┐
│ TIER 1: Cohort Builder (Every 1–6h)                       │
│  [Source] ──► RANDSTRUCT + RegAlloc Jitter (Seed_C)       │
│           ──► Pinned eBPF + vmlinux-superset.a            │
└─────────────────────────────┬─────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────┐
│ TIER 2: Profile Linker & UKI Sealer                       │
│  [Archive] ──► ld.lld --gc-sections + Cohort .BTF         │
│            ──► Pack Relocs + Sign UKI (SEV-SNP / TDX)     │
└─────────────────────────────┬─────────────────────────────┘
                              ▼
┌───────────────────────────────────────────────────────────┐
│ TIER 3: Early-Boot Self-Relinker (Every Boot, ~45ms)      │
│  [Cohort UKI] ──► Verify Hash (PCR / RTMR / SNP)          │
│               ──► CPU RDSEED + Shuffle (.text, .data)     │
│               ──► Sort Unwind/Syms + HPKE Seal & Wipe     │
└──────────────┬─────────────────────────────┬──────────────┘
               ▼                             ▼
┌────────────────────────────┐ ┌────────────────────────────┐
│ Hardened CVM / Node        │ │ Symbol & Attestation Vault │
│ • Redacted kallsyms        │ │ • Verify Cohort Signature  │
│ • Per-Boot Slab Cache Rand │ │ • Unseal Panic HPKE Seed   │
│ • Intact eBPF CO-RE & VDSO │ │ • Replay Seed -> GDB Map   │
└────────────────────────────┘ └────────────────────────────┘"""

BORDER_CHARS = set("┌─┐│└┘┬┴├┤►▼•")
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
