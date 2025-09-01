#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import socket
from collections import defaultdict

from scapy.all import rdpcap, sniff, IP, ICMP, Raw

# -------------------------
# Utilidades de impresión
# -------------------------
GREEN = "\033[92m"
RESET = "\033[0m"

def green(s: str) -> str:
    return f"{GREEN}{s}{RESET}"

# -------------------------
# Cifrado/descifrado César
# -------------------------
def caesar_shift(text: str, k: int) -> str:
    """Aplica desplazamiento -k (o sea, intenta descifrar con clave k)."""
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - k) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - k) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

# -------------------------
# Heurística "españolidad"
# -------------------------
COMMON_ES = [
    " el ", " la ", " de ", " que ", " y ", " en ", " a ", " los ", " se ",
    " del ", " por ", " un ", " para ", " con ", " no ", " una ", " su ",
    " al ", " como ", " es ", " más ", " pero ", " o ", " si ", " ya ",
    " hola ", " mundo "
]

def spanish_score(s: str) -> float:
    s_low = " " + s.lower() + " "
    score = 0.0
    # 1) palabras frecuentes
    for w in COMMON_ES:
        score += 3.0 * s_low.count(w)
    # 2) proporción de letras y espacios
    letters = sum(ch.isalpha() for ch in s)
    spaces  = s.count(" ")
    if len(s) > 0:
        score += 1.5 * (letters / len(s))
        score += 0.5 * (spaces  / len(s))
    # 3) proporción de vocales
    vowels = sum(ch.lower() in "aeiouáéíóú" for ch in s)
    if letters > 0:
        vratio = vowels / letters
        score += 1.0 - abs(vratio - 0.47)
    # 4) penaliza muchos símbolos raros
    weird = sum(ch in "@#$%^*{}[]<>\\" for ch in s)
    score -= 0.5 * weird
    return score

# -------------------------------------
# Extracción del mensaje desde paquetes
# -------------------------------------
def extract_sessions(pkts, dst_ip=None, ident=None, require_data_len=None):
    """
    Agrupa por (dst, icmp.id) y devuelve dict:
      key=(dst, ident) -> dict(seq -> char)
    Toma el primer byte del payload (estilo 'paso 2').
    """
    sessions = defaultdict(dict)

    for p in pkts:
        if not (p.haslayer(IP) and p.haslayer(ICMP)):
            continue
        ic = p[ICMP]
        if getattr(ic, "type", None) != 8:   # Echo Request
            continue

        if ident is not None and getattr(ic, "id", None) != ident:
            continue
        if dst_ip is not None and p[IP].dst != dst_ip:
            continue

        # payload
        if not p.haslayer(Raw):
            continue
        data = bytes(p[Raw].load)

        if require_data_len is not None and len(data) != require_data_len:
            continue
        if len(data) < 1:
            continue

        ch = chr(data[0])  # 1er byte = carácter (como en el paso 2)
        seq = getattr(ic, "seq", None)
        key = (p[IP].dst, getattr(ic, "id", None))

        if seq not in sessions[key]:
            sessions[key][seq] = ch

    return sessions

def reconstruct_message(seq_to_char: dict) -> str:
    """Ordena por seq y concatena caracteres."""
    parts = [seq_to_char[k] for k in sorted(seq_to_char.keys()) if k is not None]
    return "".join(parts)

# -------------------------
# Lectura: PCAP o Live
# -------------------------
def read_from_pcap(path):
    return rdpcap(path)

def read_live(iface, seconds=10, bpf_filter="icmp and icmp[icmptype]=8"):
    return sniff(iface=iface, timeout=seconds, filter=bpf_filter)

# -------------------------
# Programa principal
# -------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Decoder ICMP (paso 2) + fuerza bruta César (26 claves)."
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Ruta a captura .pcap / .pcapng")
    src.add_argument("--live", action="store_true", help="Sniff en vivo (requiere sudo)")
    ap.add_argument("--iface", help="Interfaz para --live (ej: wlo1)")
    ap.add_argument("--seconds", type=int, default=10, help="Tiempo de sniff en --live")
    ap.add_argument("--dst", help="Filtrar por IP destino (opcional)")
    ap.add_argument("--ident", type=lambda x: int(x, 0), help="Filtrar por ICMP id (ej: 0x1234 o 4660)")
    ap.add_argument("--dlen", type=int, default=56, help="Filtrar por data.len (56 por defecto)")
    args = ap.parse_args()

    if args.pcap:
        pkts = read_from_pcap(args.pcap)
    else:
        if not args.iface:
            ap.error("--live requiere --iface")
        pkts = read_live(args.iface, seconds=args.seconds)

    dst_ip = None
    if args.dst:
        try:
            dst_ip = socket.gethostbyname(args.dst)
        except Exception:
            dst_ip = args.dst

    sessions = extract_sessions(pkts, dst_ip=dst_ip, ident=args.ident, require_data_len=args.dlen)

    if not sessions:
        print("No se encontraron sesiones ICMP Echo con payload >=1 que coincidan con los filtros.")
        return

    best_key = max(sessions.keys(), key=lambda k: len(sessions[k]))
    print("\nSesiones detectadas (dst, ident) -> #paquetes:")
    for k, seqmap in sessions.items():
        print(f"  {k} -> {len(seqmap)}")

    seqmap = sessions[best_key]
    mensaje = reconstruct_message(seqmap)
    print(f"\n[Reconstrucción desde ICMP (primer byte por paquete, ordenado por seq)]")
    print(f"Mensaje bruto (cifrado César): {repr(mensaje)}\n")

    candidates = []
    for k in range(26):
        dec = caesar_shift(mensaje, k)
        candidates.append((k, dec, spanish_score(dec)))

    best = max(candidates, key=lambda t: t[2])

    print("=== Candidatos (k = clave de descifrado) ===")
    for k, dec, sc in candidates:
        line = f"[k={k:02d}] score={sc:6.3f}  {dec}"
        if (k, dec, sc) == best:
            print(green(line))
        else:
            print(line)

    print("\nMás probable:", green(f"k={best[0]} ➜ {best[1]}"))

if __name__ == "__main__":
    main()

