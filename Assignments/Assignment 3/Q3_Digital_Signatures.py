
import hashlib
import math


# COMMON HASH FUNCTION

def hash_message(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


# RSA KEY GENERATION

def rsa_key_generation():
    p = 1009
    q = 1013

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


# RSA SIGNATURE GENERATION

def rsa_sign(message, private_key):
    d, n = private_key

    digest = hash_message(message) % n

    signature = pow(digest, d, n)

    return signature


# RSA SIGNATURE VERIFICATION

def rsa_verify(message, signature, public_key):
    e, n = public_key

    digest = hash_message(message) % n

    recovered = pow(signature, e, n)

    return recovered == digest


# EXPERIMENT 1: RSA SIGNATURE

def rsa_experiment():
    print("\nEXPERIMENT 1: RSA DIGITAL SIGNATURE")
    print("=" * 65)

    public_key, private_key = rsa_key_generation()

    message = "Secure Communication"
    modified_message = "Modified Communication"

    signature = rsa_sign(message, private_key)

    print("Original Message:", message)
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    print("Digital Signature:", signature)

    print("\nValid Signature Verification:",
          rsa_verify(message, signature, public_key))

    print("Modified Message Verification:",
          rsa_verify(modified_message, signature, public_key))

    modified_signature = signature + 1

    print("Modified Signature Verification:",
          rsa_verify(message, modified_signature, public_key))

    wrong_public_key = (17, public_key[1])

    print("Wrong Public Key Verification:",
          rsa_verify(message, signature, wrong_public_key))


# DSA TOY PARAMETERS

P = 23
Q = 11
G = 2

PRIVATE_KEY = 3
PUBLIC_KEY = pow(G, PRIVATE_KEY, P)


# DSA SIGNATURE GENERATION

def dsa_sign(message, private_key, nonce):
    z = hash_message(message) % Q

    r = pow(G, nonce, P) % Q

    if r == 0:
        raise ValueError("Invalid nonce")

    nonce_inverse = pow(nonce, -1, Q)

    s = (nonce_inverse * (z + private_key * r)) % Q

    if s == 0:
        raise ValueError("Invalid signature")

    return r, s


# DSA SIGNATURE VERIFICATION

def dsa_verify(message, signature, public_key):
    r, s = signature

    if not (0 < r < Q and 0 < s < Q):
        return False

    z = hash_message(message) % Q

    w = pow(s, -1, Q)

    u1 = (z * w) % Q
    u2 = (r * w) % Q

    v = (
        (pow(G, u1, P) * pow(public_key, u2, P)) % P
    ) % Q

    return v == r


# EXPERIMENT 2: DSA SIGNATURE

def dsa_experiment():
    print("\nEXPERIMENT 2: DSA-STYLE SIGNATURE")
    print("=" * 65)

    message = "Secure Message"
    modified_message = "Changed Message"

    nonce = 7

    signature = dsa_sign(message, PRIVATE_KEY, nonce)

    print("Prime p:", P)
    print("Prime q:", Q)
    print("Generator g:", G)

    print("Private Key:", PRIVATE_KEY)
    print("Public Key:", PUBLIC_KEY)

    print("\nOriginal Message:", message)
    print("Signature (r, s):", signature)

    print("\nValid Signature Verification:",
          dsa_verify(message, signature, PUBLIC_KEY))

    print("Modified Message Verification:",
          dsa_verify(modified_message, signature, PUBLIC_KEY))

    modified_signature = (signature[0], (signature[1] + 1) % Q)

    print("Modified Signature Verification:",
          dsa_verify(message, modified_signature, PUBLIC_KEY))

    print("Wrong Public Key Verification:",
          dsa_verify(message, signature, pow(G, 5, P)))


# EXPERIMENT 3: DSA NONCE REUSE ATTACK

def nonce_reuse_experiment():
    print("\nEXPERIMENT 3: DSA NONCE REUSE ATTACK")
    print("=" * 65)

    message1 = "Payment of Rs.1000"
    message2 = "Payment of Rs.5000"

    nonce = 7

    signature1 = dsa_sign(message1, PRIVATE_KEY, nonce)
    signature2 = dsa_sign(message2, PRIVATE_KEY, nonce)

    r1, s1 = signature1
    r2, s2 = signature2

    z1 = hash_message(message1) % Q
    z2 = hash_message(message2) % Q

    print("Message 1:", message1)
    print("Message 2:", message2)

    print("\nSignature 1:", signature1)
    print("Signature 2:", signature2)

    print("\nReused Nonce:", nonce)

    if r1 != r2 or s1 == s2:
        print("Nonce recovery is not possible with this test pair.")
        return

    recovered_nonce = (
        (z1 - z2) * pow((s1 - s2) % Q, -1, Q)
    ) % Q

    recovered_private_key = (
        (s1 * recovered_nonce - z1) * pow(r1, -1, Q)
    ) % Q

    print("\nRecovered Nonce:", recovered_nonce)
    print("Actual Nonce:", nonce)

    print("Recovered Private Key:", recovered_private_key)
    print("Actual Private Key:", PRIVATE_KEY)

    print("\nNonce Recovery Successful:",
          recovered_nonce == nonce)

    print("Private Key Recovery Successful:",
          recovered_private_key == PRIVATE_KEY)


# EXPERIMENT 4: TEXTBOOK RSA MULTIPLICATIVE FORGERY

def rsa_forgery_experiment():
    print("\nEXPERIMENT 4: TEXTBOOK RSA SIGNATURE FORGERY")
    print("=" * 65)

    public_key, private_key = rsa_key_generation()

    e, n = public_key
    d, n = private_key

    m1 = 5
    m2 = 7

    s1 = pow(m1, d, n)
    s2 = pow(m2, d, n)

    forged_message = (m1 * m2) % n

    forged_signature = (s1 * s2) % n

    verification = pow(forged_signature, e, n)

    print("Message 1:", m1)
    print("Message 2:", m2)

    print("Signature 1:", s1)
    print("Signature 2:", s2)

    print("\nForged Message:", forged_message)
    print("Forged Signature:", forged_signature)

    print("Verification Result:", verification)

    print("\nTextbook RSA Forgery Successful:",
          verification == forged_message)


# MAIN PROGRAM

if __name__ == "__main__":

    print("DIGITAL SIGNATURE ANALYSIS")
    print("=" * 65)

    rsa_experiment()

    dsa_experiment()

    nonce_reuse_experiment()

    rsa_forgery_experiment()

    print("\nALL Q3 EXPERIMENTS COMPLETED")
