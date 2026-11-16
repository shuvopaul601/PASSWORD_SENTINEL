"""
Password strength analysis.

Uses the `zxcvbn` library (Dropbox's realistic password-strength estimator,
which scores against common patterns, dictionaries, and keyboard walks)
when available, and falls back to a plain Shannon-entropy estimate
otherwise.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

try:
    from zxcvbn import zxcvbn as _zxcvbn

    _HAVE_ZXCVBN = True
except ImportError:
    _HAVE_ZXCVBN = False


# Attack-scenario guess rates, used both to build the crack-time table for
# the entropy fallback and to relabel zxcvbn's own scenarios consistently.
ATTACK_SCENARIOS = [
    ("Online (throttled, 100/hr)", 100 / 3600),
    ("Online (no throttling, 10/s)", 10),
    ("Offline (slow hash, bcrypt, 1e4/s)", 1e4),
    ("Offline (fast hash, GPU, 1e10/s)", 1e10),
]


SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}


@dataclass
class StrengthResult:
    password_len: int
    method: str                      # "zxcvbn" or "entropy"
    score: int                       # 0-4
    label: str
    entropy_bits: float
    crack_time_display: str
    feedback_warning: str = ""
    feedback_suggestions: list = field(default_factory=list)
    pool_size: int = 0
    crack_times_table: list = field(default_factory=list)  # [(scenario, display)]
    pwned_count: Optional[int] = None   # None = not checked, 0 = not found, >0 = breach hits

    def pretty(self) -> str:
        lines = [
            f"Password length      : {self.password_len}",
            f"Analysis method       : {self.method}",
            f"Strength score        : {self.score}/4  ({self.label})",
            f"Estimated entropy      : {self.entropy_bits:.1f} bits",
            f"Est. time to crack      : {self.crack_time_display}",
        ]
        if self.crack_times_table:
            lines.append("Crack time by attack scenario:")
            for scenario, display in self.crack_times_table:
                lines.append(f"  - {scenario:<36}: {display}")
        if self.pwned_count is not None:
            if self.pwned_count > 0:
                lines.append(
                    f"Breach check          : FOUND in {self.pwned_count:,} "
                    f"known data breaches (HaveIBeenPwned)"
                )
            else:
                lines.append("Breach check          : not found in known breaches")
        if self.feedback_warning:
            lines.append(f"Warning                : {self.feedback_warning}")
        if self.feedback_suggestions:
            lines.append("Suggestions            :")
            for s in self.feedback_suggestions:
                lines.append(f"  - {s}")
        return "\n".join(lines)


def _charset_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # common printable symbols
    return pool or 1


def _entropy_bits(password: str) -> float:
    pool = _charset_pool_size(password)
    if not password:
        return 0.0
    return len(password) * math.log2(pool)


def _score_from_entropy(bits: float) -> int:
    if bits < 28:
        return 0
    if bits < 36:
        return 1
    if bits < 60:
        return 2
    if bits < 80:
        return 3
    return 4


def _human_crack_time(bits: float, guesses_per_second: float = 1e10) -> str:
    """Rough offline-fast-hash crack time estimate from an entropy bit count."""
    guesses = 2 ** bits
    seconds = guesses / guesses_per_second
    return _seconds_to_human(seconds)


def _seconds_to_human(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    units = [
        ("century", 60 * 60 * 24 * 365 * 100),
        ("year", 60 * 60 * 24 * 365),
        ("month", 60 * 60 * 24 * 30),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1000:
                return "centuries"
            plural = "centuries" if name == "century" else f"{name}s"
            unit = plural if value != 1 else name
            return f"{value:.1f} {unit}"
    return "less than a second"


def _crack_times_table_from_bits(bits: float) -> list:
    guesses = 2 ** bits
    table = []
    for scenario, rate in ATTACK_SCENARIOS:
        seconds = guesses / rate
        table.append((scenario, _seconds_to_human(seconds)))
    return table


def _crack_times_table_from_zxcvbn(result: dict) -> list:
    """Re-key zxcvbn's crack_times_display into the same labeled scenarios
    used for the entropy fallback, so the table always looks the same."""
    z = result.get("crack_times_display", {})
    mapping = [
        ("Online (throttled, 100/hr)", "online_throttling_100_per_hour"),
        ("Online (no throttling, 10/s)", "online_no_throttling_10_per_second"),
        ("Offline (slow hash, bcrypt, 1e4/s)", "offline_slow_hashing_1e4_per_second"),
        ("Offline (fast hash, GPU, 1e10/s)", "offline_fast_hashing_1e10_per_second"),
    ]
    table = []
    for label, key in mapping:
        if key in z:
            table.append((label, str(z[key])))
    return table


def check_pwned(password: str, timeout: float = 5.0) -> Tuple[Optional[int], Optional[str]]:
    """
    Check a password against the HaveIBeenPwned "Pwned Passwords" database
    using the k-anonymity API: only the first 5 chars of the SHA-1 hash are
    ever sent over the network, so the full password never leaves this
    machine. Returns (breach_count, error). breach_count is None if the
    check could not be completed (e.g. no network access); error then holds
    a short reason.
    """
    try:
        import requests
    except ImportError:
        return None, "requests package not installed"

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=timeout,
            headers={"User-Agent": "password-strength-analyzer"},
        )
        resp.raise_for_status()
    except Exception as exc:  # network error, timeout, DNS, etc.
        return None, f"could not reach HaveIBeenPwned ({exc.__class__.__name__})"

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1]), None
    return 0, None


def analyze_password(
    password: str,
    user_inputs: Optional[list] = None,
    check_breach: bool = False,
) -> StrengthResult:
    """
    Analyze a single password. `user_inputs` (names, dates, pet names, etc.)
    are passed to zxcvbn as a personal dictionary so it penalizes passwords
    that are built from them. If `check_breach` is True, also queries the
    HaveIBeenPwned k-anonymity API (requires network access; fails silently
    into pwned_count=None if unreachable).
    """
    user_inputs = user_inputs or []
    pwned_count = None
    if check_breach:
        pwned_count, _err = check_pwned(password)

    if _HAVE_ZXCVBN:
        result = _zxcvbn(password, user_inputs=user_inputs)
        score = result["score"]
        crack = result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
        feedback = result.get("feedback", {})
        # zxcvbn's guesses_log10 -> bits (log2(10^x) = x * log2(10))
        bits = result["guesses_log10"] * math.log2(10)
        return StrengthResult(
            password_len=len(password),
            method="zxcvbn",
            score=score,
            label=SCORE_LABELS[score],
            entropy_bits=bits,
            crack_time_display=str(crack),
            feedback_warning=feedback.get("warning", ""),
            feedback_suggestions=feedback.get("suggestions", []) or [],
            pool_size=_charset_pool_size(password),
            crack_times_table=_crack_times_table_from_zxcvbn(result),
            pwned_count=pwned_count,
        )

    # --- fallback: plain entropy heuristic ---
    bits = _entropy_bits(password)
    score = _score_from_entropy(bits)
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add symbols.")
    lowered = password.lower()
    for item in user_inputs:
        if item and item.lower() in lowered:
            suggestions.append(f"Avoid including personal info like '{item}'.")

    return StrengthResult(
        password_len=len(password),
        method="entropy (zxcvbn not installed)",
        score=score,
        label=SCORE_LABELS[score],
        entropy_bits=bits,
        crack_time_display=_human_crack_time(bits),
        feedback_suggestions=suggestions,
        pool_size=_charset_pool_size(password),
        crack_times_table=_crack_times_table_from_bits(bits),
        pwned_count=pwned_count,
    )
