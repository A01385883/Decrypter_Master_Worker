"""
Extrae los pares (mensaje, hash_real) de autenticación MD5 (RFC 2082) de un
archivo .pcap con tráfico RIPv2. Cada paquete autenticado con la misma
keyid comparte la misma clave secreta, así que podemos usar varios pares
como "pruebas cruzadas" para confirmar con alta confianza que una clave
candidata es la correcta (no solo coincide en un hash por azar).
"""

from scapy.all import rdpcap, raw
from scapy.layers.rip import RIP, RIPAuth


def extraer_pares(ruta_pcap: str, keyid_objetivo: int | None = None) -> list[dict]:
    """
    Recorre el pcap y regresa una lista de dicts, uno por cada paquete RIP
    con autenticación MD5 (authtype 2 al inicio):
        {
            "indice": índice del paquete en el pcap,
            "src": IP origen,
            "keyid": ID de la clave usada,
            "seqnum": número de secuencia del paquete,
            "mensaje_hex": bytes a hashear, en hex,
            "hash_real": digest MD5 capturado, en hex (32 caracteres)
        }

    Si `keyid_objetivo` se especifica, solo regresa los pares que usan esa keyid
    (útil si el pcap mezcla tráfico firmado con distintas claves).
    """
    paquetes = rdpcap(ruta_pcap)
    pares = []

    for i, p in enumerate(paquetes):
        if RIP not in p or RIPAuth not in p:
            continue

        rip_layer = p[RIP]
        auth_layer = p[RIPAuth]

        # Solo nos interesa la entrada de autenticación tipo 2 (MD5), la que
        # trae digestoffset/keyid/seqnum -- ignoramos el trailer (tipo 1) aquí.
        if auth_layer.authtype != 3:  # en scapy, RIPAuth con AF=0xFFFF y authtype=3 => md5
            continue

        keyid = auth_layer.keyid
        if keyid_objetivo is not None and keyid != keyid_objetivo:
            continue

        payload = raw(rip_layer)  # bytes crudos de TODO el mensaje RIP (header + entries + trailer)
        offset = auth_layer.digestoffset

        mensaje_bytes = payload[:offset]
        trailer = payload[offset:]

        if len(trailer) < 20:
            # No parece traer trailer completo (AFI+authtype+16 bytes digest)
            continue

        digest = trailer[4:20]  # los primeros 4 bytes del trailer son AFI(2)+authtype(2)

        pares.append({
            "indice": i,
            "src": p['IP'].src if p.haslayer('IP') else None,
            "keyid": keyid,
            "seqnum": auth_layer.seqnum,
            "mensaje_hex": mensaje_bytes.hex(),
            "hash_real": digest.hex(),
        })

    return pares


if __name__ == "__main__":
    import sys
    import json

    ruta = sys.argv[1] if len(sys.argv) > 1 else "rip_passkey_size_06_01.pcap"
    pares = extraer_pares(ruta)

    print(f"Se encontraron {len(pares)} paquetes autenticados con MD5.\n")
    for par in pares:
        print(json.dumps(par, indent=2))
        print()
