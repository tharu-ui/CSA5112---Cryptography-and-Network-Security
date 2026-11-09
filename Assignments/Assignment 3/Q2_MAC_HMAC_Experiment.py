
import hashlib
import hmac

# TOY MERKLE-DAMGARD HASH

BLOCK_SIZE = 8
INITIAL_VALUE = 0x12345678
MASK = 0xFFFFFFFF


def padding(length):
    pad = b'\x80'

    while (length + len(pad) + 4) % BLOCK_SIZE != 0:
        pad += b'\x00'

    pad += (length * 8).to_bytes(4, 'big')
    return pad


def compress(state, block):
    value = int.from_bytes(block, 'big')

    state = ((state ^ value) * 0x45D9F3B + 0x27100001) & MASK

    return state


def process_blocks(state, data):
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        state = compress(state, block)

    return state


def toy_hash(message):
    data = message + padding(len(message))

    state = process_blocks(INITIAL_VALUE, data)

    return state.to_bytes(4, 'big')


# LENGTH EXTENSION CONTINUATION

def continue_hash(digest, processed_length, suffix):
    state = int.from_bytes(digest, 'big')

    final_length = processed_length + len(suffix)

    data = suffix + padding(final_length)

    state = process_blocks(state, data)

    return state.to_bytes(4, 'big')


# NAIVE MAC

def naive_mac(key, message):
    return toy_hash(key + message)


# TOY HMAC CONSTRUCTION

def xor_bytes(data, value):
    return bytes(byte ^ value for byte in data)


# HMAC USING STANDARD SHA-256

def toy_hmac(key, message):
    return hmac.new(
        key,
        message,
        hashlib.sha256
    ).digest()


# VERIFICATION FUNCTIONS

def verify_hash(message, digest):
    return toy_hash(message) == digest


def verify_naive_mac(key, message, mac):
    return naive_mac(key, message) == mac


def verify_hmac(key, message, mac):
    expected_mac = toy_hmac(key, message)

    return hmac.compare_digest(expected_mac, mac)


# EXPERIMENT 1: PLAIN HASH

def hash_experiment():
    print("\nEXPERIMENT 1: PLAIN HASH VERIFICATION")
    print("=" * 65)

    message = b"Transfer Rs.1000"
    digest = hashlib.sha256(message).hexdigest()

    modified = b"Transfer Rs.9000"

    print("Original Message:", message.decode())
    print("Original SHA-256:", digest)

    print("\nOriginal Message Verification:",
          hashlib.sha256(message).hexdigest() == digest)

    print("Modified Message with Original Digest:",
          hashlib.sha256(modified).hexdigest() == digest)

    attacker_digest = hashlib.sha256(modified).hexdigest()

    print("Modified Message with Recomputed Digest:",
          hashlib.sha256(modified).hexdigest() == attacker_digest)

    print("\nObservation: A plain hash cannot authenticate the sender.")


# EXPERIMENT 2: NAIVE MAC

def naive_mac_experiment():
    print("\nEXPERIMENT 2: NAIVE MAC VERIFICATION")
    print("=" * 65)

    key = b"SecretKey"
    message = b"Transfer Rs.1000"

    original_mac = naive_mac(key, message)

    modified = b"Transfer Rs.9000"
    appended = message + b" APPROVED"

    print("Original Message:", message.decode())
    print("Original MAC:", original_mac.hex())

    print("\nOriginal Message Verification:",
          verify_naive_mac(key, message, original_mac))

    print("Modified Message Verification:",
          verify_naive_mac(key, modified, original_mac))

    print("Appended Message Verification:",
          verify_naive_mac(key, appended, original_mac))


# EXPERIMENT 3: LENGTH EXTENSION ATTACK

def length_extension_attack():
    print("\nEXPERIMENT 3: LENGTH EXTENSION ATTACK")
    print("=" * 65)

    secret_key = b"SecretKey"
    message = b"Transfer Rs.1000"
    suffix = b"&admin=true"

    original_mac = naive_mac(secret_key, message)

    guessed_key_length = len(secret_key)

    glue_padding = padding(guessed_key_length + len(message))

    forged_message = message + glue_padding + suffix

    processed_length = (
        guessed_key_length + len(message) + len(glue_padding)
    )

    forged_mac = continue_hash(
        original_mac,
        processed_length,
        suffix
    )

    print("Original Message:", message.decode())
    print("Original MAC:", original_mac.hex())

    print("Appended Data:", suffix.decode())
    print("Guessed Key Length:", guessed_key_length)

    print("Attacker Knows the Secret Key: No")

    print("Forged MAC:", forged_mac.hex())

    print("\nForged Message Accepted by Server:",
          verify_naive_mac(
              secret_key,
              forged_message,
              forged_mac
          ))

    print("\nObservation: The attacker successfully extended the message")
    print("without knowing the secret key.")


# EXPERIMENT 4: HMAC SECURITY VERIFICATION

def hmac_experiment():
    print("\nEXPERIMENT 4: HMAC SECURITY VERIFICATION")
    print("=" * 65)

    key = b"SecretKey"
    message = b"Transfer Rs.1000"

    original_hmac = toy_hmac(key, message)

    modified = b"Transfer Rs.9000"
    appended = message + b" APPROVED"

    modified_hmac = bytearray(original_hmac)
    modified_hmac[0] ^= 1

    print("Original Message:", message.decode())
    print("Original HMAC:", original_hmac.hex())

    print("\nOriginal Message with Original HMAC:",
          verify_hmac(key, message, original_hmac))

    print("Modified Message with Original HMAC:",
          verify_hmac(key, modified, original_hmac))

    print("Appended Message with Original HMAC:",
          verify_hmac(key, appended, original_hmac))

    print("Original Message with Modified HMAC:",
          verify_hmac(key, message, bytes(modified_hmac)))

    print("Modified Message with Newly Generated HMAC:",
          verify_hmac(key, modified, toy_hmac(key, modified)))


# EXPERIMENT 5: COMPARISON

def comparison_experiment():
    print("\nEXPERIMENT 5: SECURITY COMPARISON")
    print("=" * 85)

    print(f"{'Mechanism':<20} {'Integrity':<15} {'Authentication':<20} {'Length Extension'}")
    print("-" * 85)

    print(f"{'Plain Hash':<20} {'Limited':<15} {'No':<20} {'Not Applicable'}")
    print(f"{'Naive MAC':<20} {'Yes':<15} {'Yes':<20} {'Vulnerable'}")
    print(f"{'HMAC':<20} {'Yes':<15} {'Yes':<20} {'Resistant'}")

    print("\nNote: The toy hash and toy HMAC are educational demonstrations.")
    print("Real applications must use standard SHA-256 and HMAC-SHA-256.")


# MAIN PROGRAM

if __name__ == "__main__":

    print("CRYPTOGRAPHIC HASH, MAC AND HMAC ANALYSIS")
    print("=" * 65)

    hash_experiment()

    naive_mac_experiment()

    length_extension_attack()

    hmac_experiment()

    comparison_experiment()

    print("\nALL Q2 EXPERIMENTS COMPLETED")
