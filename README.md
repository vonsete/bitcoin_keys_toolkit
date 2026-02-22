# Bitcoin Key Toolkit

A single interactive Python script that consolidates Bitcoin key conversion utilities into a menu-driven CLI.

## Features

| Option | Description |
|--------|-------------|
| 1 | Private key (hex) → WIF |
| 2 | Private key (hex) → XPRV (BIP32 extended private key) |
| 3 | Private key (hex) → BIP32 child key at custom derivation path (WIF) |
| 4 | WIF → Private key (hex) + XPRV |
| 5 | XPRV → Private key (hex) |
| 6 | BIP39: given 11 mnemonic words, find the valid 12th |

## Requirements

```
bip32utils
base58
mnemonic
```

Install dependencies:

```bash
pip install bip32utils base58 mnemonic
```

## Usage

```bash
python3 bitcoin_toolkit.py
```

```
═══════════════════════════════════════════════════════
         Bitcoin Key Toolkit
═══════════════════════════════════════════════════════
  [1] Clave privada hex  →  WIF
  [2] Clave privada hex  →  XPRV (BIP32)
  [3] Clave privada hex  →  Child key BIP32 (WIF)
  [4] WIF                →  Clave privada hex + XPRV
  [5] XPRV               →  Clave privada hex
  [6] BIP39: 11 palabras →  Encontrar la 12ª
  [0] Salir
═══════════════════════════════════════════════════════
```

## Key format notes

- **WIF compressed**: 52 chars, starts with `K` or `L` (mainnet)
- **WIF uncompressed**: 51 chars, starts with `5` (mainnet)
- **XPRV**: 111 chars, starts with `xprv`
- **Private key hex**: 64 hex characters (32 bytes)

## Warning

Keep your private keys secure. Never share them or enter them into untrusted software.
