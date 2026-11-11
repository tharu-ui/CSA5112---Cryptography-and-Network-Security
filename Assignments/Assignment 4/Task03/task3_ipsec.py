
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SPI = 1001
WINDOW = 4

key = AESGCM.generate_key(bit_length=128)
salt = os.urandom(4)

class SecurityAssociation:
    def __init__(self):
        self.highest = 0
        self.received = set()
        self.aes = AESGCM(key)

def encrypt_packet(seq, message):
    nonce = salt + seq.to_bytes(8, "big")
    aad = struct.pack("!II", SPI, seq)
    encrypted = AESGCM(key).encrypt(nonce, message.encode(), aad)
    return SPI, seq, nonce, encrypted

def receive_packet(packet, sa):
    spi, seq, nonce, encrypted = packet

    print("\nSPI:", spi)
    print("Sequence:", seq)

    if spi != SPI:
        print("DROP: Unknown SPI")
        return

    if seq in sa.received:
        print("DROP: Replay detected")
        return

    if sa.highest and seq <= sa.highest - WINDOW:
        print("DROP: Outside replay window")
        return

    try:
        aad = struct.pack("!II", spi, seq)
        message = sa.aes.decrypt(nonce, encrypted, aad)
    except Exception:
        print("DROP: Integrity verification failed")
        return

    # Update the replay window only after authentication.
    sa.received.add(seq)
    sa.highest = max(sa.highest, seq)
    sa.received = {
        n for n in sa.received if n > sa.highest - WINDOW
    }

    print("ICV: PASS")
    print("Window:", max(1, sa.highest-WINDOW+1), "to", sa.highest)
    print("ACCEPT:", message.decode())

sa = SecurityAssociation()

print("TASK 3: IPsec ESP SIMULATION")
print("SPI:", SPI)
print("Replay window:", WINDOW)

p1 = encrypt_packet(1, "Packet one")
p2 = encrypt_packet(2, "Packet two")

print("\n--- Normal transmission ---")
receive_packet(p1, sa)
receive_packet(p2, sa)

print("\n--- Replay attack ---")
receive_packet(p1, sa)

print("\n--- Reordered packet ---")
receive_packet(encrypt_packet(3, "Packet three"), sa)

print("\n--- Window boundary test ---")
receive_packet(encrypt_packet(7, "Packet seven"), sa)
receive_packet(encrypt_packet(3, "Old packet"), sa)

print("\n--- Tampering test ---")
p = encrypt_packet(8, "Original message")
damaged = bytearray(p[3])
damaged[-1] ^= 1
receive_packet((p[0], p[1], p[2], bytes(damaged)), sa)

print("\n--- Unknown SPI test ---")
p = encrypt_packet(9, "Unknown SPI")
receive_packet((9999, p[1], p[2], p[3]), sa)
