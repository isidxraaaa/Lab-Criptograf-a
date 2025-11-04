from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import DES, DES3, AES
import base64

# ---------- Ajuste de claves ----------

def ajustar_clave_des(k_bytes: bytes) -> bytes:
    target = 8
    if len(k_bytes) < target:
        k_bytes = k_bytes + get_random_bytes(target - len(k_bytes))
    elif len(k_bytes) > target:
        k_bytes = k_bytes[:target]
    return k_bytes

def ajustar_clave_aes256(k_bytes: bytes) -> bytes:
    target = 32
    if len(k_bytes) < target:
        k_bytes = k_bytes + get_random_bytes(target - len(k_bytes))
    elif len(k_bytes) > target:
        k_bytes = k_bytes[:target]
    return k_bytes

def ajustar_clave_3des(k_bytes: bytes) -> bytes:
    if len(k_bytes) <= 16:
        target = 16
    elif len(k_bytes) <= 24:
        target = 24
    else:
        target = 24

    if len(k_bytes) < target:
        k_bytes = k_bytes + get_random_bytes(target - len(k_bytes))
    elif len(k_bytes) > target:
        k_bytes = k_bytes[:target]

    try:
        k_bytes = DES3.adjust_key_parity(k_bytes)
    except ValueError:
        tmp = bytearray(k_bytes)
        tmp[0] ^= 0x01
        k_bytes = DES3.adjust_key_parity(bytes(tmp))
    return k_bytes

# ---------- Entrada por algoritmo (cifrado) ----------

def pedir_des():
    print("\n--- DES ---")
    key = input("Ingrese la clave (DES): ").strip()
    iv = input("Ingrese el IV (DES): ").strip()
    texto = input("Ingrese el texto a cifrar (DES): ").strip()
    k_final = ajustar_clave_des(key.encode("utf-8"))
    print(f"Clave final DES (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "DES", "key_bytes": k_final, "iv": iv, "texto": texto}

def pedir_aes():
    print("\n--- AES-256 ---")
    key = input("Ingrese la clave (AES-256): ").strip()
    iv = input("Ingrese el IV (AES-256): ").strip()
    texto = input("Ingrese el texto a cifrar (AES-256): ").strip()
    k_final = ajustar_clave_aes256(key.encode("utf-8"))
    print(f"Clave final AES-256 (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "AES-256", "key_bytes": k_final, "iv": iv, "texto": texto}

def pedir_3des():
    print("\n--- 3DES ---")
    key = input("Ingrese la clave (3DES): ").strip()
    iv = input("Ingrese el IV (3DES): ").strip()
    texto = input("Ingrese el texto a cifrar (3DES): ").strip()
    k_final = ajustar_clave_3des(key.encode("utf-8"))
    print(f"Clave final 3DES (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "3DES", "key_bytes": k_final, "iv": iv, "texto": texto}

# ---------- Entrada por algoritmo (descifrado) ----------

def pedir_des_descifrar():
    print("\n--- DES (descifrar) ---")
    key = input("Ingrese la clave (DES): ").strip()
    iv = input("Ingrese el IV (DES): ").strip()
    ct = leer_ciphertext()
    k_final = ajustar_clave_des(key.encode("utf-8"))
    print(f"Clave final DES (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "DES", "key_bytes": k_final, "iv": iv, "ciphertext": ct}

def pedir_aes_descifrar():
    print("\n--- AES-256 (descifrar) ---")
    key = input("Ingrese la clave (AES-256): ").strip()
    iv = input("Ingrese el IV (AES-256): ").strip()
    ct = leer_ciphertext()
    k_final = ajustar_clave_aes256(key.encode("utf-8"))
    print(f"Clave final AES-256 (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "AES-256", "key_bytes": k_final, "iv": iv, "ciphertext": ct}

def pedir_3des_descifrar():
    print("\n--- 3DES (descifrar) ---")
    key = input("Ingrese la clave (3DES): ").strip()
    iv = input("Ingrese el IV (3DES): ").strip()
    ct = leer_ciphertext()
    k_final = ajustar_clave_3des(key.encode("utf-8"))
    print(f"Clave final 3DES (hex): {k_final.hex()}  (len={len(k_final)})")
    return {"alg": "3DES", "key_bytes": k_final, "iv": iv, "ciphertext": ct}

# ---------- Lectura y validación simple del IV ----------

def pedir_iv_bytes(iv_str: str, expected_len: int, etiqueta: str) -> bytes:
    iv = iv_str.encode("utf-8")
    while len(iv) != expected_len:
        print(f"IV de longitud {len(iv)} bytes. Se requieren exactamente {expected_len} bytes para {etiqueta}.")
        iv = input(f"Ingrese nuevamente el IV para {etiqueta}: ").strip().encode("utf-8")
    return iv

# ---------- PKCS#7 ----------

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Datos no alineados al tamaño de bloque.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding PKCS#7 inválido.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding PKCS#7 inválido (bytes finales).")
    return data[:-pad_len]

# ---------- Cifrado/Descifrado (CBC) ----------

def cifrar_descifrar_des(key: bytes, iv: bytes, texto: str):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    pt_padded = pkcs7_pad(texto.encode("utf-8"), 8)
    ct = cipher.encrypt(pt_padded)
    cipher_d = DES.new(key, DES.MODE_CBC, iv=iv)
    pt_unpadded = pkcs7_unpad(cipher_d.decrypt(ct), 8)
    return ct, pt_unpadded

def cifrar_descifrar_3des(key: bytes, iv: bytes, texto: str):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt_padded = pkcs7_pad(texto.encode("utf-8"), 8)
    ct = cipher.encrypt(pt_padded)
    cipher_d = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt_unpadded = pkcs7_unpad(cipher_d.decrypt(ct), 8)
    return ct, pt_unpadded

def cifrar_descifrar_aes(key: bytes, iv: bytes, texto: str):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_padded = pkcs7_pad(texto.encode("utf-8"), 16)
    ct = cipher.encrypt(pt_padded)
    cipher_d = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_unpadded = pkcs7_unpad(cipher_d.decrypt(ct), 16)
    return ct, pt_unpadded

def descifrar_des(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt, 8)

def descifrar_3des(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt, 8)

def descifrar_aes(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt, 16)

# ---------- Helpers ----------

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def bhex(b: bytes) -> str:
    return b.hex()

def leer_ciphertext() -> bytes:
    while True:
        m = input("¿Formato de ciphertext? [1] Base64  [2] HEX: ").strip()
        if m == "1":
            s = input("Ingrese ciphertext en Base64: ").strip()
            try:
                return base64.b64decode(s, validate=True)
            except Exception:
                print("Base64 inválido. Intente nuevamente.")
        elif m == "2":
            s = input("Ingrese ciphertext en HEX (sin 0x): ").strip().replace(" ", "")
            try:
                return bytes.fromhex(s)
            except ValueError:
                print("HEX inválido. Intente nuevamente.")
        else:
            print("Opción no válida. Elija 1 o 2.")

# ---------- Main ----------

def main():
    print("Bienvenidx, este programa sirve para cifrar y descifrar mensajes con los algoritmos DES, AES-256 y 3DES.\n")
    print("Elija su algoritmo: DES, AES o 3DES")
    while True:
        eleccion = input("Algoritmo: ").strip().upper()
        if eleccion in {"DES", "AES", "3DES"}:
            break
        print("Opción inválida. Escriba DES, AES o 3DES.")

    print("\n¿Desea cifrar o descifrar?")
    while True:
        oper = input("Escriba CIFRAR/DESCIFRAR: ").strip().upper()
        if oper in {"CIFRAR", "DESCIFRAR"}:
            break
        print("Opción inválida. Escriba CIFRAR o DESCIFRAR.")

    if eleccion == "DES":
        if oper == "CIFRAR":
            datos = pedir_des()
            iv_bytes = pedir_iv_bytes(datos["iv"], 8, "DES")
            ct, pt = cifrar_descifrar_des(datos["key_bytes"], iv_bytes, datos["texto"])
            print("\n--- CIFRADO DES ---")
            print(f"Ciphertext (Base64): {b64(ct)}")
            print(f"Ciphertext (HEX):    {bhex(ct)}")
            print(f"Texto descifrado (verificación): {pt.decode('utf-8', errors='replace')}")
        else:
            datos = pedir_des_descifrar()
            iv_bytes = pedir_iv_bytes(datos["iv"], 8, "DES")
            pt = descifrar_des(datos["key_bytes"], iv_bytes, datos["ciphertext"])
            print("\n--- DESCIFRADO DES ---")
            print(f"Plaintext: {pt.decode('utf-8', errors='replace')}")

    elif eleccion == "3DES":
        if oper == "CIFRAR":
            datos = pedir_3des()
            iv_bytes = pedir_iv_bytes(datos["iv"], 8, "3DES")
            ct, pt = cifrar_descifrar_3des(datos["key_bytes"], iv_bytes, datos["texto"])
            print("\n--- CIFRADO 3DES ---")
            print(f"Ciphertext (Base64): {b64(ct)}")
            print(f"Ciphertext (HEX):    {bhex(ct)}")
            print(f"Texto descifrado (verificación): {pt.decode('utf-8', errors='replace')}")
        else:
            datos = pedir_3des_descifrar()
            iv_bytes = pedir_iv_bytes(datos["iv"], 8, "3DES")
            pt = descifrar_3des(datos["key_bytes"], iv_bytes, datos["ciphertext"])
            print("\n--- DESCIFRADO 3DES ---")
            print(f"Plaintext: {pt.decode('utf-8', errors='replace')}")

    else:  # AES
        if oper == "CIFRAR":
            datos = pedir_aes()
            iv_bytes = pedir_iv_bytes(datos["iv"], 16, "AES-256")
            ct, pt = cifrar_descifrar_aes(datos["key_bytes"], iv_bytes, datos["texto"])
            print("\n--- CIFRADO AES-256 ---")
            print(f"Ciphertext (Base64): {b64(ct)}")
            print(f"Ciphertext (HEX):    {bhex(ct)}")
            print(f"Texto descifrado (verificación): {pt.decode('utf-8', errors='replace')}")
        else:
            datos = pedir_aes_descifrar()
            iv_bytes = pedir_iv_bytes(datos["iv"], 16, "AES-256")
            pt = descifrar_aes(datos["key_bytes"], iv_bytes, datos["ciphertext"])
            print("\n--- DESCIFRADO AES-256 ---")
            print(f"Plaintext: {pt.decode('utf-8', errors='replace')}")

if __name__ == "__main__":
    main()
