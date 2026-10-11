#!/usr/bin/env python3
"""
Password Strength Checker
Personal cybersecurity project.

Evaluates passwords using:
- Length
- Character diversity
- Common/dictionary-style patterns
- Repetition and sequential patterns
- Actionable recommendations

For privacy, passwords are processed locally and are never saved.
"""

import argparse
import getpass
import re
from dataclasses import dataclass, field
from typing import List


COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "admin", "admin123", "welcome",
    "letmein", "iloveyou", "monkey", "dragon", "football",
    "abc123", "111111", "000000", "passw0rd"
}

SEQUENTIAL_PATTERNS = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


@dataclass
class StrengthResult:
    score: int
    label: str
    checks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def has_sequential_pattern(password: str, minimum: int = 4) -> bool:
    """Return True when the password contains an obvious sequence."""
    lowered = password.lower()
    for sequence in SEQUENTIAL_PATTERNS:
        for i in range(len(sequence) - minimum + 1):
            chunk = sequence[i:i + minimum]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_repeated_pattern(password: str) -> bool:
    """Return True for repeated single characters or short repeated chunks."""
    if re.search(r"(.)\1{2,}", password):
        return True
    return bool(re.search(r"(.{2,4})\1", password))


def contains_dictionary_pattern(password: str) -> bool:
    """Check exact/common-password style patterns."""
    normalized = re.sub(r"[^a-z0-9]", "", password.lower())
    if normalized in COMMON_PASSWORDS:
        return True

    # Catch common words followed by simple digits.
    return bool(re.fullmatch(
        r"(password|admin|welcome|qwerty|letmein|football|iloveyou)\d{0,4}",
        normalized
    ))


def check_password(password: str) -> StrengthResult:
    """Evaluate password strength without storing the password."""
    score = 0
    checks = []
    recommendations = []

    length = len(password)
    if length >= 16:
        score += 30
        checks.append("Length: excellent (16+ characters).")
    elif length >= 12:
        score += 24
        checks.append("Length: good (12–15 characters).")
    elif length >= 8:
        score += 15
        checks.append("Length: acceptable (8–11 characters).")
    else:
        checks.append("Length: weak (under 8 characters).")
        recommendations.append("Use at least 12–16 characters.")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))

    diversity = sum([has_lower, has_upper, has_digit, has_symbol])
    score += diversity * 10

    if diversity == 4:
        checks.append("Character diversity: excellent (lower/upper/digit/symbol).")
    elif diversity == 3:
        checks.append("Character diversity: good.")
    elif diversity == 2:
        checks.append("Character diversity: limited.")
    else:
        checks.append("Character diversity: weak.")

    if not has_lower:
        recommendations.append("Add lowercase letters.")
    if not has_upper:
        recommendations.append("Add uppercase letters.")
    if not has_digit:
        recommendations.append("Add numbers.")
    if not has_symbol:
        recommendations.append("Add symbols.")

    if contains_dictionary_pattern(password):
        score -= 25
        checks.append("Common/dictionary pattern: detected.")
        recommendations.append("Avoid common passwords, names, dictionary words, and predictable word+number combinations.")
    else:
        score += 10
        checks.append("Common/dictionary pattern: not detected.")

    if has_sequential_pattern(password):
        score -= 15
        checks.append("Sequential pattern: detected.")
        recommendations.append("Avoid sequences such as 1234, abcd, qwerty, or their reversed forms.")
    else:
        score += 5
        checks.append("Sequential pattern: not detected.")

    if has_repeated_pattern(password):
        score -= 10
        checks.append("Repeated pattern: detected.")
        recommendations.append("Avoid repeated characters or repeated short chunks.")
    else:
        score += 5
        checks.append("Repeated pattern: not detected.")

    score = max(0, min(100, score))

    if score >= 80:
        label = "Very Strong"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Moderate"
    elif score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    if not recommendations:
        recommendations.append("Good password hygiene. Use a unique password and store it in a password manager.")

    return StrengthResult(score, label, checks, recommendations)


def print_result(result: StrengthResult) -> None:
    print("\n" + "=" * 55)
    print(f"Password Strength: {result.label}")
    print(f"Score: {result.score}/100")
    print("=" * 55)

    print("\nChecks:")
    for item in result.checks:
        print(f"  • {item}")

    print("\nRecommendations:")
    for item in result.recommendations:
        print(f"  • {item}")

    print("\nPrivacy: password input is evaluated locally and is not saved.")
    print("=" * 55)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate password strength locally."
    )
    parser.add_argument(
        "--password",
        help="Password to evaluate. Omit this option to enter it securely."
    )
    args = parser.parse_args()

    password = args.password if args.password is not None else getpass.getpass(
        "Enter password (input hidden): "
    )

    result = check_password(password)
    print_result(result)


if __name__ == "__main__":
    main()
