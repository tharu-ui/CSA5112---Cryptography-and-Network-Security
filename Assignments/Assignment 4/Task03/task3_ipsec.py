
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Configuration
SPI = 1001
WINDOW_SIZE = 4
MAX_SEQUENCE = (2 ** 32) - 1

# Generate a temporary session key
key = AESGCM.generate_key(bit_length=128)


# SENDER SIDE
class SenderSA:

    def __init__(self, key, spi, max_seq=MAX_SEQUENCE):
        self.aes = AESGCM(key)
        self.spi = spi
        self.salt = os.urandom(4)
        self.next_seq = 1
        self.max_seq = max_seq

    def protect(self, message):

        if self.next_seq > self.max_seq:
            raise OverflowError("Sequence number exhausted")

        seq = self.next_seq
        self.next_seq += 1

        nonce = self.salt + seq.to_bytes(8, "big")
        aad = struct.pack("!II", self.spi, seq)

        encrypted = self.aes.encrypt(
            nonce, message.encode(), aad
        )

        return {
            "spi": self.spi,
            "seq": seq,
            "nonce": nonce,
            "ciphertext": encrypted
        }


# RECEIVER SIDE
class ReceiverSA:

    def __init__(self, key, spi, window_size):
        self.aes = AESGCM(key)
        self.spi = spi
        self.window_size = window_size
        self.highest = 0
        self.received = set()

    def receive(self, packet):

        spi = packet["spi"]
        seq = packet["seq"]

        print("\nSPI received:", spi)
        print("SA lookup:", "Searching...")

        # Security Association lookup
        if spi != self.spi:
            self.drop("Unknown SPI")
            return

        print("SA lookup: Successful")
        print("Sequence number:", seq)

        if seq < 1 or seq > MAX_SEQUENCE:
            self.drop("Invalid sequence number")
            return

        # Integrity verification BEFORE updating replay state
        aad = struct.pack("!II", spi, seq)

        try:
            plaintext = self.aes.decrypt(
                packet["nonce"],
                packet["ciphertext"],
                aad
            )
            print("ICV verification: PASS")

        except InvalidTag:
            self.drop("ICV verification failed")
            return

        # Replay-window validation
        if self.highest > 0:
            window_start = self.highest - self.window_size + 1

            if seq < window_start:
                self.drop("Packet outside replay window")
                return

        if seq in self.received:
            self.drop("Duplicate packet / replay detected")
            return

        # Update state only after successful authentication
        if seq > self.highest:
            self.highest = seq

            window_start = max(
                1, self.highest - self.window_size + 1
            )

            self.received = {
                n for n in self.received if n >= window_start
            }

        self.received.add(seq)

        window_start = max(
            1, self.highest - self.window_size + 1
        )

        print("Replay window:",
              window_start, "to", self.highest)

        print("Received sequence numbers:",
              sorted(self.received))

        print("Decapsulated packet:", plaintext.decode())
        print("INTERNAL LOG: ACCEPT")
        print("SENDER-VISIBLE RESULT: ACCEPT")

    def drop(self, reason):

        # Detailed reason is kept in the local security log.
        print("INTERNAL SECURITY LOG: DROP -", reason)

        # Do not reveal the specific failure to the sender.
        print("SENDER-VISIBLE RESULT: DROP")


# MANUAL DESK-CHECK: TASK 3.4
def desk_check():

    print("\n================================")
    print("TASK 3.4: REPLAY WINDOW DESK CHECK")
    print("================================")

    arrivals = [
        (1, True),
        (2, True),
        (5, True),
        (3, True),
        (2, True),
        (9, True),
        (4, True),
        (7, False),
        (7, True)
    ]

    highest = 0
    received = set()

    for order, (seq, icv_valid) in enumerate(arrivals, 1):

        if not icv_valid:
            decision = "DROP - Invalid ICV"

        elif highest > 0 and seq < highest - WINDOW_SIZE + 1:
            decision = "DROP - Outside window"

        elif seq in received:
            decision = "DROP - Duplicate"

        else:
            if seq > highest:
                highest = seq

                start = max(
                    1, highest - WINDOW_SIZE + 1
                )

                received = {
                    n for n in received if n >= start
                }

            received.add(seq)
            decision = "ACCEPT"

        start = max(1, highest - WINDOW_SIZE + 1)

        print(
            "Arrival:", order,
            "| Sequence:", seq,
            "| Highest:", highest,
            "| Window:", start, "to", max(highest, 0),
            "| Received:", sorted(received),
            "| Decision:", decision
        )


# MAIN PROGRAM
print("================================")
print("IPSEC ESP PACKET PROCESSOR")
print("================================")

sender = SenderSA(key, SPI)
receiver = ReceiverSA(key, SPI, WINDOW_SIZE)

print("\nSTAGE A: NORMAL ESP TUNNEL MODE")

print("Outer IP header:")
print("Source: 198.51.100.1")
print("Destination: 203.0.113.1")

for message in [
    "Inner IP: 10.0.1.10 -> 10.0.2.20 | TCP | Data 1",
    "Inner IP: 10.0.1.10 -> 10.0.2.20 | TCP | Data 2"
]:

    print("\nSending protected packet...")
    packet = sender.protect(message)
    receiver.receive(packet)


print("\nSTAGE B: REPLAY AND REORDERING")

# Delay sequence 3 while packets 4 and 5 arrive
p3 = sender.protect("Delayed packet 3")
p4 = sender.protect("Packet 4")
p5 = sender.protect("Packet 5")

print("\nW/2 delay test: Deliver 4, 5, then 3")
receiver.receive(p4)
receiver.receive(p5)
receiver.receive(p3)

print("\nExact replay test: Resend packet 3")
receiver.receive(p3)

# Hold packet 6 and packet 8
p6 = sender.protect("Delayed packet 6")
p7 = sender.protect("Packet 7")
p8 = sender.protect("Window boundary packet 8")
p9 = sender.protect("Packet 9")
p10 = sender.protect("Packet 10")
p11 = sender.protect("Packet 11")

print("\nDeliver packets 7, 9, 10 and 11")
receiver.receive(p7)
receiver.receive(p9)
receiver.receive(p10)
receiver.receive(p11)

print("\nExact window boundary test: Deliver packet 8")
receiver.receive(p8)

print("\nMore than W delay test: Deliver packet 6")
receiver.receive(p6)


print("\nSTAGE C: TAMPERING AND MISCONFIGURATION")

# Modified sequence number
p12 = sender.protect("Sequence modification test")
modified_seq = p12.copy()
modified_seq["seq"] = 13

print("\nModified sequence number test")
receiver.receive(modified_seq)

# Modified encrypted payload
p13 = sender.protect("Payload tampering test")
damaged = p13.copy()

changed = bytearray(damaged["ciphertext"])
changed[0] ^= 1
damaged["ciphertext"] = bytes(changed)

print("\nModified payload byte test")
receiver.receive(damaged)

# Unknown SPI
p14 = sender.protect("Unknown SPI test")
unknown_spi = p14.copy()
unknown_spi["spi"] = 9999

print("\nUnknown SPI test")
receiver.receive(unknown_spi)

# Sequence exhaustion / rekey demonstration
print("\nSequence exhaustion test")

small_sender = SenderSA(key, SPI, max_seq=2)
small_sender.protect("Sequence 1")
small_sender.protect("Sequence 2")

try:
    small_sender.protect("Sequence 3")

except OverflowError:
    print("INTERNAL LOG: Sequence space exhausted")
    print("Action: Rekey required")
    print("New SA must be established before sending more packets")


# Task 3.4 manual trace
desk_check()

print("\n================================")
print("IPSEC ESP TESTING COMPLETED")
print("================================")
