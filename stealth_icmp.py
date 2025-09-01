#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
from scapy.all import IP, ICMP, send, hexdump

# -------------------------------
# 1) Cifrado César (del punto 2.1)
# -------------------------------
def cifrado_cesar(texto: str, corrimiento: int) -> str:
    res = []
    for c in texto:
        if c.isupper():
            res.append(chr((ord(c) - 65 + corrimiento) % 26 + 65))
        elif c.islower():
            res.append(chr((ord(c) - 97 + corrimiento) % 26 + 97))
        else:
            # deja espacios, comas, etc. tal cual
            res.append(c)
    return "".join(res)

# ----------------------------------------------------------------
# 2) Payload "discreto": exactamente 56 bytes como ping de Linux
#    - primer byte = carácter cifrado
#    - los 55 restantes = patrón secuencial 0x01..0x37 (para mimetizar)
#    (si prefieres 0x00..0x37 con el 0x00, lo reemplaza el primer byte)
# ----------------------------------------------------------------
def payload_56_bytes(primer_char: str) -> bytes:
    if len(primer_char) != 1:
        raise ValueError("primer_char debe ser un solo carácter")
    # patrón típico incremental: 0x00..0x37 (56 bytes)
    patron = bytes(range(0, 56))
    # sustituimos SOLO el primer byte por tu carácter cifrado
    # (si el char no es ASCII de 1 byte, lo degradamos a '?')
    try:
        b = primer_char.encode("ascii")
        if len(b) != 1:
            b = b"?"
    except UnicodeEncodeError:
        b = b"?"
    return b + patron[1:]  # total 56

# ---------------------------------------------------------
# 3) Envío: 1 ICMP Echo por cada carácter del mensaje cifrado
#    - ICMP id ≈ PID (como hace /bin/ping)
#    - ICMP seq: 0,1,2,...
# ---------------------------------------------------------
def enviar_icmp_stealth(destino_host: str, mensaje_cifrado: str, enviar=True, ident=None, seq_start=0):
    # Resuelve una IP de google.cl
    dst_ip = socket.gethostbyname(destino_host)
    print(f"[INFO] Destino {destino_host} → {dst_ip}")

    # Identificador parecido a ping de Linux
    if ident is None:
        ident = os.getpid() & 0xFFFF
    print(f"[INFO] ICMP identifier (ident): 0x{ident:04x}")

    for i, ch in enumerate(mensaje_cifrado):
        seq = seq_start + i
        pay = payload_56_bytes(ch)                # <-- relleno de 56 bytes
        pkt = IP(dst=dst_ip) / ICMP(id=ident, seq=seq, type=8, code=0) / pay

        print(f"\n--- Paquete #{i} (seq={seq}) ---")
        pkt.show()
        print("Hexdump (solo data):")
        hexdump(pay)

        if enviar:
            send(pkt, verbose=0)

if __name__ == "__main__":
    destino = "google.cl"
    texto = input("Ingrese el texto a cifrar: ")
    corr  = int(input("Ingrese el corrimiento: "))

    msg_cif = cifrado_cesar(texto, corr)
    print(f"[INFO] Mensaje cifrado: {msg_cif!r}")

    # Enviar realmente (ejecuta el script con sudo)
    enviar_icmp_stealth(destino, msg_cif, enviar=True, ident=None, seq_start=0)
    print("\n[INFO] Envío finalizado.")
