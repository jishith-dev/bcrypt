
# bcrypt for Zen

Secure bcrypt password hashing and verification for the Zen programming language.

Powered by the Openwall `crypt_blowfish` implementation with native C integration.

## Features

- Secure bcrypt password hashing.
- Password verification.
- Configurable cost factor.
- Random salt generation.
- Constant-time hash comparison.
- Python bcrypt compatibility tested.
- Native C implementation.
- Zen `extern fn` integration.
- Supports special characters and Unicode passwords.

## Installation

Install through the Zen package manager:

```bash
zen install bcrypt
```

Or clone the repository manually:

```bash
git clone https://github.com/Jishith-dev/bcrypt.git
```

## Usage

```zen
import (Bcrypt) from "bcrypt"

Bcrypt b

string password = "hello123"

string hash = b.hash(
  password,
  10
)

screen(hash)

bool valid = b.verify(
  password,
  hash
)

screen(valid)
```

## API

### `b.hash(password, cost)`

Generates a bcrypt password hash.

| Parameter | Type | Description |
|---|---|---|
| `password` | `string` | Password to hash |
| `cost` | `int` | Bcrypt cost factor |

Returns:

```text
string
```

Example:

```zen
string hash = b.hash("hello123", 10)
```

### `b.verify(password, hash)`

Verifies a password against a bcrypt hash.

| Parameter | Type | Description |
|---|---|---|
| `password` | `string` | Password to verify |
| `hash` | `string` | Stored bcrypt hash |

Returns:

```text
bool
```

Example:

```zen
bool valid = b.verify(
  "hello123",
  hash
)
```

## Cost Factor

The cost factor controls the computational work required by bcrypt.

Examples:

```zen
string hash4 = b.hash("hello123", 4)

string hash10 = b.hash("hello123", 10)

string hash12 = b.hash("hello123", 12)
```

Use a cost factor appropriate for your deployment environment.

## Compatibility

Compatibility testing has been performed between Zen and Python's bcrypt implementation.

| Direction | Result |
|---|---|
| Zen-generated hash → Python verification | Passed |
| Python-generated hash → Zen verification | Passed |

Tested cost factors:

- Cost 4
- Cost 6
- Cost 10
- Cost 12

Tested cases:

- Basic passwords
- Wrong passwords
- Special characters
- Unicode passwords
- Empty passwords
- Long passwords
- Case sensitivity
- Random salts

## Portability

The package uses a portable C bcrypt implementation.

Windows and other platforms may require native build adjustments because the current random-source implementation uses POSIX APIs.

## Security Notes

- Store bcrypt hashes, not plaintext passwords.
- Never store passwords in logs.
- Use a suitable cost factor for your application.
- Do not compare plaintext passwords with stored hashes manually.
- Bcrypt has a maximum effective password input length of 72 bytes.

## Native Implementation

This package uses the Openwall `crypt_blowfish` implementation.

Native source files:

- `native/native.c`
- `native/crypt_blowfish.c`
- `native/crypt_gensalt.c`

## Version

Current version: **1.0.0**

## Author

Jishith-dev

## License

MIT 
