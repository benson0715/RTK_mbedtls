# Realtek LALU HW-crypto mbedtls (RTS5918)

This is `zephyrproject-rtos/mbedtls` **v3.6.2** (base commit
`a78176c6ff0733ba08018cba4447bd3f20de7978`) plus the Realtek LALU
hardware-crypto integration for the RTS5918 EC, used as TF-M's secure
`mbedcrypto`.

## What was added / changed
- `library/lalu/` — the LALU engine drivers (SHA-2, AES, DMAC, PKE/ECDSA-P256,
  key manager).
- `library/CMakeLists.txt` — builds the `lalu/*.c` into `mbedcrypto` and sets the
  enable flags (see below).
- Surgical hooks in `sha256.c`, `sha512.c`, `ecp.c`, `ecdsa.c`, `gcm.c`,
  `common.h`, `platform.c`, `platform_util.c`, `include/mbedtls/gcm.h` to route
  the corresponding primitives to the LALU engine.

Everything is gated by compile definitions (set in `library/CMakeLists.txt`), so
a plain non-RTK build is unaffected when they are absent.

## Feature status (as delivered)
| Flag | Primitive | State |
|------|-----------|-------|
| `CONFIG_ENABLE_LALU_SHA2` | SHA-256 / SHA-512 | **HW** ✅ |
| `CONFIG_ENABLE_LALU_PKE_ECDSA` | ECP scalar-mul (P-256, ECDSA verify path) | **HW** ✅ |
| `CONFIG_ENABLE_LALU_AES` | AES engine driver present | built |
| ~~`CONFIG_ENABLE_LALU_GCM`~~ | AES-GCM | **kept in SOFTWARE** — LALU GCM HW path bus-stalls at runtime (unresolved) |
| `MBEDTLS_ALLOW_PRIVATE_ACCESS` | — | required: lalu drivers touch mbedtls struct fields by name |

## Consuming this repo
Point the `mbedtls` module at this repo (replaces the stock
`modules/crypto/mbedtls`). The TF-M side (BL2 LALU clock/reset/mutex bring-up in
`boot_hal_bl2.c`, and `lib/ext/mbedcrypto/mbedcrypto_config/`) is delivered with
the TF-M port, not here. The `framework` submodule
(`https://github.com/Mbed-TLS/mbedtls-framework`) is fetched as usual.

See the project bring-up notes for the HW register bases, SAU carve-out for PKE
(`0x40080000-0x400BFFFF`), and the GCM/PKE header-graft caveats.
