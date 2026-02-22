# -*- coding: utf-8 -*-

import hashlib
import binascii
import bip32utils
import base58
from mnemonic import Mnemonic

# ─── Constantes ──────────────────────────────────────────────────────────────

BASE58_CHARS = (
    '123456789'
    'ABCDEFGHJKLMNPQRSTUVWXYZ'
    'abcdefghijkmnopqrstuvwxyz'
)


# ─── Funciones de conversión ──────────────────────────────────────────────────

def hex_to_wif(private_key_hex, compressed=True):
    """Clave privada hex → WIF."""
    data = "80" + private_key_hex
    if compressed:
        data += "01"
    hash1 = hashlib.sha256(bytes.fromhex(data)).digest()
    hash2 = hashlib.sha256(hash1).hexdigest()
    checksum = hash2[:8]
    data += checksum

    i = int(data, 16)
    result = ''
    while i > 0:
        i, remainder = divmod(i, 58)
        result = BASE58_CHARS[remainder] + result
    return result


def wif_to_hex(wif):
    """WIF → (clave privada hex, red, comprimida)."""
    decoded = base58.b58decode(wif)

    prefix = decoded[0]
    if prefix == 0x80:
        network = "Mainnet"
    elif prefix == 0xEF:
        network = "Testnet"
    else:
        raise ValueError(f"Prefijo no reconocido: {hex(prefix)}")

    # WIF comprimida: 38 bytes (1 prefix + 32 key + 1 flag + 4 checksum)
    # WIF sin comprimir: 37 bytes (1 prefix + 32 key + 4 checksum)
    if len(decoded) == 38:
        compressed = True
        private_key_hex = decoded[1:33].hex()
    elif len(decoded) == 37:
        compressed = False
        private_key_hex = decoded[1:33].hex()
    else:
        raise ValueError(f"Longitud WIF incorrecta: {len(decoded)} bytes (esperado 37 o 38)")

    return private_key_hex, network, compressed


def hex_to_xprv(private_key_hex):
    """Clave privada hex → XPRV (BIP32 extended private key)."""
    private_key_bytes = binascii.unhexlify(private_key_hex)
    root_key = bip32utils.BIP32Key.fromEntropy(private_key_bytes)
    return root_key.ExtendedKey()


def xprv_to_hex(xprv):
    """XPRV → clave privada hex (32 bytes del payload BIP32)."""
    # Estructura XPRV decodificada (82 bytes totales):
    #   [0:4]   version (4 bytes)
    #   [4]     depth (1 byte)
    #   [5:9]   fingerprint (4 bytes)
    #   [9:13]  child index (4 bytes)
    #   [13:45] chain code (32 bytes)
    #   [45]    key prefix 0x00 (1 byte)
    #   [46:78] clave privada (32 bytes)
    #   [78:82] checksum (4 bytes)
    xprv_bytes = base58.b58decode(xprv)
    return xprv_bytes[46:78].hex()


def hex_to_bip32_child(private_key_hex, path=(0, 0)):
    """Clave privada hex → child key BIP32 en WIF y pubkey hex."""
    private_key_bytes = binascii.unhexlify(private_key_hex)
    root_key = bip32utils.BIP32Key.fromEntropy(private_key_bytes)
    child = root_key
    for idx in path:
        child = child.ChildKey(idx)
    return child.WalletImportFormat(), child.PublicKey().hex()


def encontrar_12_palabra(palabras_11, idioma="english"):
    """Dado 11 palabras BIP39, encuentra la 12ª por fuerza bruta."""
    mnemo = Mnemonic(idioma)
    for palabra in mnemo.wordlist:
        frase = palabras_11 + [palabra]
        if mnemo.check(' '.join(frase)):
            return palabra
    return None


# ─── Helpers de UI ───────────────────────────────────────────────────────────

def separador():
    print("─" * 55)

def titulo(texto):
    separador()
    print(f"  {texto}")
    separador()

def pedir_hex_key(prompt="Clave privada hex (64 chars): "):
    key = input(prompt).strip()
    if len(key) != 64:
        raise ValueError(f"Se esperaban 64 caracteres hex, se recibieron {len(key)}")
    return key

def pedir_si_no(prompt, default_si=True):
    sufijo = "[S/n]" if default_si else "[s/N]"
    resp = input(f"{prompt} {sufijo}: ").strip().lower()
    if resp == '':
        return default_si
    return resp in ('s', 'si', 'y', 'yes')


# ─── Handlers de cada opción ─────────────────────────────────────────────────

def opcion_hex_a_wif():
    titulo("Clave privada hex → WIF")
    key = pedir_hex_key()
    compressed = pedir_si_no("¿Clave comprimida?", default_si=True)
    wif = hex_to_wif(key, compressed)
    print(f"\n  WIF: {wif}")


def opcion_hex_a_xprv():
    titulo("Clave privada hex → XPRV")
    key = pedir_hex_key()
    xprv = hex_to_xprv(key)
    print(f"\n  XPRV: {xprv}")


def opcion_hex_a_child():
    titulo("Clave privada hex → Child key BIP32")
    key = pedir_hex_key()
    path_str = input("Ruta de derivación (ej: 0/0, por defecto 0/0): ").strip()
    path = tuple(int(x) for x in path_str.split("/")) if path_str else (0, 0)
    wif, pubkey = hex_to_bip32_child(key, path)
    path_display = "m/" + "/".join(str(x) for x in path)
    print(f"\n  Ruta:       {path_display}")
    print(f"  Child WIF:  {wif}")
    print(f"  Public key: {pubkey}")


def opcion_wif_a_todo():
    titulo("WIF → Clave privada hex + XPRV")
    wif = input("WIF: ").strip()
    try:
        priv_hex, network, compressed = wif_to_hex(wif)
        xprv = hex_to_xprv(priv_hex)
        print(f"\n  Red:          {network}")
        print(f"  Comprimida:   {'Sí' if compressed else 'No'}")
        print(f"  Privada hex:  {priv_hex}")
        print(f"  XPRV:         {xprv}")
    except ValueError as e:
        print(f"\n  Error: {e}")


def opcion_xprv_a_hex():
    titulo("XPRV → Clave privada hex")
    xprv = input("XPRV: ").strip()
    try:
        priv_hex = xprv_to_hex(xprv)
        print(f"\n  Privada hex: {priv_hex}")
    except Exception as e:
        print(f"\n  Error: {e}")


def opcion_12_palabras():
    titulo("BIP39: Encontrar la 12ª palabra")
    print("  Introduce las 11 palabras separadas por espacios:")
    palabras_str = input("  > ").strip()
    palabras = palabras_str.split()
    if len(palabras) != 11:
        print(f"\n  Error: se necesitan 11 palabras, se ingresaron {len(palabras)}")
        return
    idioma = input("  Idioma [english]: ").strip() or "english"
    print("\n  Buscando... (puede tardar unos segundos)")
    palabra_12 = encontrar_12_palabra(palabras, idioma)
    if palabra_12:
        frase = ' '.join(palabras + [palabra_12])
        print(f"\n  12ª palabra:    {palabra_12}")
        print(f"  Frase completa: {frase}")
    else:
        print("\n  No se encontró una 12ª palabra válida.")


# ─── Menú principal ───────────────────────────────────────────────────────────

OPCIONES = [
    ("1", "Clave privada hex  →  WIF",                   opcion_hex_a_wif),
    ("2", "Clave privada hex  →  XPRV (BIP32)",           opcion_hex_a_xprv),
    ("3", "Clave privada hex  →  Child key BIP32 (WIF)",  opcion_hex_a_child),
    ("4", "WIF                →  Clave privada hex + XPRV", opcion_wif_a_todo),
    ("5", "XPRV               →  Clave privada hex",      opcion_xprv_a_hex),
    ("6", "BIP39: 11 palabras →  Encontrar la 12ª",       opcion_12_palabras),
    ("0", "Salir",                                        None),
]

def mostrar_menu():
    print("\n" + "═" * 55)
    print("         Bitcoin Key Toolkit")
    print("═" * 55)
    for clave, descripcion, _ in OPCIONES:
        print(f"  [{clave}] {descripcion}")
    print("═" * 55)
    return input("  Opción: ").strip()


def main():
    while True:
        opcion = mostrar_menu()
        handler = None
        for clave, _, fn in OPCIONES:
            if opcion == clave:
                handler = fn
                break

        if handler is None and opcion == "0":
            print("\n  Hasta luego.\n")
            break
        elif handler:
            print()
            try:
                handler()
            except Exception as e:
                print(f"\n  Error inesperado: {e}")
        else:
            print("\n  Opción no válida.")


if __name__ == "__main__":
    main()
