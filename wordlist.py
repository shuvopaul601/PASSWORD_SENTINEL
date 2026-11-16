"""
Custom wordlist generator.

Builds a targeted wordlist from personal data points (name, pet, important
dates, etc.) the way tools like CUPP do: base words are case-varied,
leetspeak-mangled, combined with each other, and suffixed with years /
common numbers / common symbols.

Intended for authorized use: auditing the strength of your own accounts,
or penetration testing you are explicitly authorized to perform.
"""

from __future__ import annotations

import itertools
import re
from datetime import date
from typing import Iterable, List, Set

LEET_MAP = {
    "a": ["a", "4", "@"],
    "b": ["b", "8"],
    "e": ["e", "3"],
    "g": ["g", "9"],
    "i": ["i", "1", "!"],
    "l": ["l", "1"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "z": ["z", "2"],
}

COMMON_SUFFIXES = ["", "!", "!!", "#", "@", "123", "1234", "007", "01", "99"]
COMMON_PREFIXES = ["", "!", "@", "#"]


def _clean_tokens(raw_inputs: Iterable[str]) -> List[str]:
    """Split raw input strings into clean base tokens (words / number chunks)."""
    tokens: Set[str] = set()
    for raw in raw_inputs:
        if not raw:
            continue
        raw = raw.strip()
        if not raw:
            continue
        # split on whitespace and non-alphanumeric separators, keep pieces
        pieces = re.split(r"[^A-Za-z0-9]+", raw)
        for p in pieces:
            if p:
                tokens.add(p)
        # also keep the original compact (no separators) form
        compact = re.sub(r"[^A-Za-z0-9]+", "", raw)
        if compact:
            tokens.add(compact)
    return sorted(tokens)


def _case_variants(word: str) -> Set[str]:
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    # toggle-case (sWaP cAsE) for shorter words only, to limit blow-up
    if len(word) <= 10:
        swapped = "".join(
            c.lower() if c.isupper() else c.upper() for c in word
        )
        variants.add(swapped)
    return variants


def _leetspeak_variants(word: str, max_variants: int = 8) -> Set[str]:
    """Generate a bounded set of leetspeak substitutions for a word."""
    choices = []
    for ch in word:
        lower = ch.lower()
        options = LEET_MAP.get(lower)
        if options:
            # preserve original case for the plain option, substitute digits/symbols otherwise
            opts = []
            for o in options:
                if o == lower:
                    opts.append(ch)
                else:
                    opts.append(o)
            choices.append(opts)
        else:
            choices.append([ch])

    variants: Set[str] = set()
    for combo in itertools.product(*choices):
        variants.add("".join(combo))
        if len(variants) >= max_variants:
            break
    return variants


def _years_range(center: int = None, span: int = 30) -> List[str]:
    """A reasonable range of 4-digit and 2-digit years for append-year patterns."""
    this_year = center or date.today().year
    years = []
    for y in range(this_year - span, this_year + 1):
        years.append(str(y))
        years.append(str(y)[-2:])
    return sorted(set(years))


def generate_wordlist(
    inputs: List[str],
    include_years: bool = True,
    year_span: int = 30,
    include_leet: bool = True,
    include_suffixes: bool = True,
    combine_pairs: bool = True,
    min_length: int = 4,
    max_length: int = 32,
    limit: int = 200_000,
) -> List[str]:
    """
    Generate a custom wordlist from a list of raw personal-info strings
    (e.g. ["John Smith", "2021-05-14", "Rex", "Acme Corp"]).

    Returns a sorted, deduplicated list of candidate passwords.
    """
    base_tokens = _clean_tokens(inputs)
    if not base_tokens:
        return []

    words: Set[str] = set()

    # 1. base tokens with case variants (+ leetspeak)
    for tok in base_tokens:
        for cv in _case_variants(tok):
            words.add(cv)
            if include_leet:
                words.update(_leetspeak_variants(cv))

    # 2. pairwise combinations of distinct tokens (name+pet, name+date, etc.)
    if combine_pairs and len(base_tokens) > 1:
        pair_base: Set[str] = set()
        for a, b in itertools.permutations(base_tokens, 2):
            for ca in (a, a.capitalize(), a.lower()):
                for cb in (b, b.capitalize(), b.lower()):
                    pair_base.add(ca + cb)
                    pair_base.add(ca + "_" + cb)
                    pair_base.add(ca + "." + cb)
            if len(pair_base) > 2000:
                break
        words.update(pair_base)

    # 3. years + common suffixes/prefixes appended to every word collected so far
    expanded: Set[str] = set(words)
    suffixes = list(COMMON_SUFFIXES) if include_suffixes else [""]
    prefixes = list(COMMON_PREFIXES) if include_suffixes else [""]
    years = _years_range(span=year_span) if include_years else []

    for w in words:
        for suf in suffixes:
            expanded.add(w + suf)
        for pre in prefixes:
            expanded.add(pre + w)
        for y in years:
            expanded.add(w + y)
            expanded.add(y + w)
        if len(expanded) > limit:
            break

    # 4. filter by length, dedupe, sort
    final = sorted(
        {w for w in expanded if min_length <= len(w) <= max_length}
    )
    return final[:limit]


def export_wordlist(words: List[str], path: str) -> int:
    """Write words to a .txt file, one per line. Returns the count written."""
    with open(path, "w", encoding="utf-8") as f:
        for w in words:
            f.write(w + "\n")
    return len(words)


def wordlist_stats(words: List[str]) -> dict:
    """Summary stats for a generated wordlist: count, length range/histogram,
    and a small preview sample — used by the CLI/GUI to show what was built."""
    if not words:
        return {
            "count": 0, "min_length": 0, "max_length": 0,
            "length_histogram": {}, "sample": [],
        }

    lengths = [len(w) for w in words]
    histogram: dict = {}
    for n in lengths:
        histogram[n] = histogram.get(n, 0) + 1

    return {
        "count": len(words),
        "min_length": min(lengths),
        "max_length": max(lengths),
        "length_histogram": dict(sorted(histogram.items())),
        "sample": words[:10],
    }
