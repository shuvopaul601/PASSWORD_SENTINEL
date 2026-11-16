#!/usr/bin/env python3
"""
Password Strength Analyzer + Custom Wordlist Generator
--------------------------------------------------------
For auditing the strength of your own passwords, and generating
targeted wordlists for AUTHORIZED password-strength testing only
(e.g. testing your own accounts, or systems you have explicit
permission to test). Do not use generated wordlists against
accounts or systems you do not own or have authorization to test.

Usage:
  python cli.py analyze                       # interactive prompt
  python cli.py analyze -p "MyP@ssw0rd" -u John -u Rex -u 2021-05-14
  python cli.py wordlist -i "John" -i "Rex" -i "2021-05-14" -o out.txt
  python cli.py gui                            # launch the PyQt6 desktop application
"""

from __future__ import annotations

import argparse
import getpass
import sys

from strength import analyze_password
from wordlist import export_wordlist, generate_wordlist, wordlist_stats


def cmd_analyze(args: argparse.Namespace) -> None:
    password = args.password
    if not password:
        password = getpass.getpass("Enter password to analyze (input hidden): ")
    if not password:
        print("No password provided.", file=sys.stderr)
        sys.exit(1)

    result = analyze_password(
        password,
        user_inputs=args.user_input or [],
        check_breach=args.check_pwned,
    )
    print()
    print(result.pretty())


def cmd_batch(args: argparse.Namespace) -> None:
    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.rstrip("\n") for line in f if line.strip()]
    except OSError as exc:
        print(f"Could not read {args.file}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not passwords:
        print("No passwords found in file.", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {len(passwords)} passwords from {args.file}...\n")
    header = f"{'PASSWORD':<24}{'SCORE':<8}{'LABEL':<14}{'ENTROPY':<10}{'CRACK TIME (fast GPU)'}"
    print(header)
    print("-" * len(header))
    for pw in passwords:
        result = analyze_password(pw, user_inputs=args.user_input or [],
                                   check_breach=args.check_pwned)
        shown = pw if not args.mask else pw[:2] + "*" * max(len(pw) - 2, 0)
        print(
            f"{shown:<24}{result.score}/4{'':<5}{result.label:<14}"
            f"{result.entropy_bits:<10.1f}{result.crack_time_display}"
        )


def cmd_wordlist(args: argparse.Namespace) -> None:
    inputs = args.input or []
    if not inputs:
        print("Provide at least one -i/--input value (name, date, pet, etc.)",
              file=sys.stderr)
        sys.exit(1)

    words = generate_wordlist(
        inputs,
        include_years=not args.no_years,
        year_span=args.year_span,
        include_leet=not args.no_leet,
        include_suffixes=not args.no_suffixes,
        combine_pairs=not args.no_combine,
        min_length=args.min_length,
        max_length=args.max_length,
        limit=args.limit,
    )
    count = export_wordlist(words, args.output)
    print(f"Generated {count} candidate passwords -> {args.output}")

    if args.stats:
        stats = wordlist_stats(words)
        print(f"\nLength range : {stats['min_length']}-{stats['max_length']}")
        print("Length histogram:")
        for length, n in stats["length_histogram"].items():
            bar = "#" * max(1, n * 40 // max(stats["count"], 1))
            print(f"  {length:>3} chars | {bar} {n}")
        print("\nSample:")
        for w in stats["sample"]:
            print(f"  {w}")


def cmd_gui(_args: argparse.Namespace) -> None:
    import gui
    gui.main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer + Custom Wordlist Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze password strength")
    p_analyze.add_argument("-p", "--password", help="Password to analyze "
                            "(omit to be prompted securely)")
    p_analyze.add_argument("-u", "--user-input", action="append",
                            help="Personal info to penalize if reused "
                                 "(repeatable: -u John -u Rex)")
    p_analyze.add_argument("--check-pwned", action="store_true",
                            help="Check password against the HaveIBeenPwned "
                                 "breach database (k-anonymity API, needs "
                                 "internet; the full password is never sent)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_batch = sub.add_parser("batch", help="Analyze many passwords from a file")
    p_batch.add_argument("file", help="Text file, one password per line")
    p_batch.add_argument("-u", "--user-input", action="append",
                          help="Personal info to penalize if reused "
                               "(repeatable)")
    p_batch.add_argument("--check-pwned", action="store_true",
                          help="Also check each password against HaveIBeenPwned")
    p_batch.add_argument("--mask", action="store_true",
                          help="Mask passwords in the printed report")
    p_batch.set_defaults(func=cmd_batch)

    p_word = sub.add_parser("wordlist", help="Generate a custom wordlist")
    p_word.add_argument("-i", "--input", action="append", required=True,
                         help="Personal info seed (repeatable): name, pet, "
                              "date (YYYY-MM-DD), company, etc.")
    p_word.add_argument("-o", "--output", default="wordlist.txt",
                         help="Output .txt path (default: wordlist.txt)")
    p_word.add_argument("--no-years", action="store_true",
                         help="Don't append year patterns")
    p_word.add_argument("--year-span", type=int, default=30,
                         help="How many years back from today to include "
                              "(default: 30)")
    p_word.add_argument("--no-leet", action="store_true",
                         help="Don't generate leetspeak variants")
    p_word.add_argument("--no-suffixes", action="store_true",
                         help="Don't append common suffixes/prefixes "
                              "(!, 123, @, etc.)")
    p_word.add_argument("--no-combine", action="store_true",
                         help="Don't combine pairs of inputs together")
    p_word.add_argument("--min-length", type=int, default=4)
    p_word.add_argument("--max-length", type=int, default=32)
    p_word.add_argument("--limit", type=int, default=200_000,
                         help="Max number of candidates to write "
                              "(default: 200000)")
    p_word.add_argument("--stats", action="store_true",
                         help="Print a length histogram and sample after generating")
    p_word.set_defaults(func=cmd_wordlist)

    p_gui = sub.add_parser("gui", help="Launch the PyQt6 desktop application")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
