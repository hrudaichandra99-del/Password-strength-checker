# Password Strength Checker

A Python-based personal cybersecurity project that evaluates password strength locally using regex-based checks and common weakness patterns.

## Features

- Real-time password strength evaluation
- Length analysis
- Lowercase/uppercase/number/symbol diversity checks
- Common-password and dictionary-style pattern detection
- Sequential pattern detection (`1234`, `abcd`, `qwerty`, etc.)
- Repeated character/chunk detection
- 0–100 strength score
- Actionable security recommendations
- Hidden terminal input using Python `getpass`
- Unit tests
- No password storage or network transmission

## Project Structure

```text
password_strength_checker/
├── password_checker.py
├── test_password_checker.py
└── README.md
```

## Requirements

- Python 3.8+
- No external packages required

## Run

```bash
python password_checker.py
```

The password is entered with hidden terminal input.

For testing a value directly:

```bash
python password_checker.py --password "ExamplePassword123!"
```

> For real passwords, prefer the secure hidden-input mode rather than putting the password in your shell history.

## Run Tests

```bash
python -m unittest -v
```

## Scoring Logic

The checker considers:

1. Password length
2. Character diversity
3. Common/dictionary patterns
4. Sequential patterns
5. Repeated patterns

The final score is normalized to 0–100 and mapped to:

- 0–19: Very Weak
- 20–39: Weak
- 40–59: Moderate
- 60–79: Strong
- 80–100: Very Strong

## Security Notes

This is an educational password-strength estimator, not a replacement for a password manager or a production-grade password policy engine.

A strong password should be:

- Long and unique
- Not reused across websites
- Free from personal information
- Stored in a reputable password manager
- Protected with MFA where available

The project intentionally does not save passwords, log them, hash them, or send them over a network.

## Resume Description

**Password Strength Checker — Personal Project**

- Built a Python-based password strength checker using regex pattern matching to evaluate length, character diversity, common-password patterns, sequential patterns, and repeated characters.
- Developed a 0–100 scoring model with actionable recommendations to help users create stronger, more unique passwords.
- Added secure hidden terminal input and unit tests, demonstrating practical understanding of authentication security and defensive programming.
