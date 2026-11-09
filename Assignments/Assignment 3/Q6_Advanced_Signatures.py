
import hashlib
import math


# COMMON HASH FUNCTIONS

def hash_value(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)


def truncated_hash(message, bits=16):
    digest = hashlib.sha256(message.encode()).digest()
    value = int.from_bytes(digest, "big")
    return value >> (256 - bits)


# ==================================================
# EXPERIMENT 1: RSA SIGNATURE
# ==================================================

def rsa_key_generation():
    p = 1009
    q = 1013

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 17
    d = pow(e, -1, phi)

    return (e, n), (d, n)


def rsa_sign(message, private_key):
    d, n = private_key
    digest = hash_value(message) % n

    return pow(digest, d, n)


def rsa_verify(message, signature, public_key):
    e, n = public_key
    digest = hash_value(message) % n

    return pow(signature, e, n) == digest


def rsa_experiment():
    print("\nEXPERIMENT 1: RSA SIGNATURE")
    print("=" * 65)

    public_key, private_key = rsa_key_generation()

    message = "Secure Digital Transaction"
    modified_message = "Modified Digital Transaction"

    signature = rsa_sign(message, private_key)

    print("Message:", message)
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    print("Signature:", signature)

    print("\nValid Signature:",
          rsa_verify(message, signature, public_key))

    print("Modified Message:",
          rsa_verify(modified_message, signature, public_key))


# ==================================================
# EXPERIMENT 2: DSA / DSS SIGNATURE
# ==================================================

P = 23
Q = 11
G = 2

DSA_PRIVATE = 3
DSA_PUBLIC = pow(G, DSA_PRIVATE, P)


def dsa_sign(message, private_key, nonce):
    z = hash_value(message) % Q

    r = pow(G, nonce, P) % Q

    if r == 0 or math.gcd(nonce, Q) != 1:
        raise ValueError("Invalid DSA nonce")

    s = (
        pow(nonce, -1, Q) *
        (z + private_key * r)
    ) % Q

    if s == 0:
        raise ValueError("Invalid DSA signature")

    return r, s


def dsa_verify(message, signature, public_key):
    r, s = signature

    if not (0 < r < Q and 0 < s < Q):
        return False

    z = hash_value(message) % Q
    w = pow(s, -1, Q)

    u1 = (z * w) % Q
    u2 = (r * w) % Q

    v = (
        pow(G, u1, P) *
        pow(public_key, u2, P)
    ) % P

    v = v % Q

    return v == r


def dsa_experiment():
    print("\nEXPERIMENT 2: DSA / DSS SIGNATURE")
    print("=" * 65)

    message = "Digital Signature Scheme"

    signature = dsa_sign(message, DSA_PRIVATE, 7)

    print("Prime p:", P)
    print("Prime q:", Q)
    print("Generator g:", G)
    print("Private Key:", DSA_PRIVATE)
    print("Public Key:", DSA_PUBLIC)

    print("\nMessage:", message)
    print("Signature (r, s):", signature)

    print("Valid Signature:",
          dsa_verify(message, signature, DSA_PUBLIC))

    print("Modified Message:",
          dsa_verify("Changed Message", signature, DSA_PUBLIC))


# ==================================================
# EXPERIMENT 3: ECDSA SIGNATURE
# ==================================================

EC_P = 17
EC_A = 2
EC_B = 2
EC_G = (5, 1)
EC_N = 19

EC_PRIVATE = 7


def point_add(p1, p2):
    if p1 is None:
        return p2

    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % EC_P == 0:
        return None

    if p1 == p2:
        slope = (
            (3 * x1 * x1 + EC_A) *
            pow(2 * y1, -1, EC_P)
        ) % EC_P

    else:
        slope = (
            (y2 - y1) *
            pow((x2 - x1) % EC_P, -1, EC_P)
        ) % EC_P

    x3 = (slope * slope - x1 - x2) % EC_P
    y3 = (slope * (x1 - x3) - y1) % EC_P

    return x3, y3


def point_multiply(k, point):
    result = None
    current = point

    while k > 0:
        if k & 1:
            result = point_add(result, current)

        current = point_add(current, current)
        k >>= 1

    return result


def ecdsa_sign(message, private_key, nonce):
    z = hash_value(message) % EC_N

    point = point_multiply(nonce, EC_G)

    if point is None:
        raise ValueError("Invalid nonce")

    r = point[0] % EC_N

    if r == 0:
        raise ValueError("Invalid ECDSA r")

    s = (
        pow(nonce, -1, EC_N) *
        (z + r * private_key)
    ) % EC_N

    if s == 0:
        raise ValueError("Invalid ECDSA s")

    return r, s


def ecdsa_verify(message, signature, public_key):
    r, s = signature

    if not (0 < r < EC_N and 0 < s < EC_N):
        return False

    z = hash_value(message) % EC_N
    w = pow(s, -1, EC_N)

    u1 = (z * w) % EC_N
    u2 = (r * w) % EC_N

    p1 = point_multiply(u1, EC_G)
    p2 = point_multiply(u2, public_key)

    point = point_add(p1, p2)

    if point is None:
        return False

    return point[0] % EC_N == r


def ecdsa_experiment():
    print("\nEXPERIMENT 3: ECDSA SIGNATURE")
    print("=" * 65)

    message = "Elliptic Curve Digital Signature"

    public_key = point_multiply(EC_PRIVATE, EC_G)

    signature = ecdsa_sign(message, EC_PRIVATE, 3)

    print("Curve: y^2 = x^3 + 2x + 2 mod 17")
    print("Generator:", EC_G)
    print("Private Key:", EC_PRIVATE)
    print("Public Key:", public_key)

    print("\nMessage:", message)
    print("Signature (r, s):", signature)

    print("Valid Signature:",
          ecdsa_verify(message, signature, public_key))

    print("Modified Message:",
          ecdsa_verify("Changed Message", signature, public_key))


# ==================================================
# EXPERIMENT 4: ELGAMAL SIGNATURE
# ==================================================

EL_P = 467
EL_ALPHA = 2
EL_PRIVATE = 127

EL_PUBLIC = pow(EL_ALPHA, EL_PRIVATE, EL_P)


def elgamal_sign(message, private_key, nonce):
    p = EL_P

    if not (1 < nonce < p - 1):
        raise ValueError("Invalid nonce")

    if math.gcd(nonce, p - 1) != 1:
        raise ValueError("Nonce must be coprime to p-1")

    z = hash_value(message) % (p - 1)

    r = pow(EL_ALPHA, nonce, p)

    s = (
        pow(nonce, -1, p - 1) *
        (z - private_key * r)
    ) % (p - 1)

    return r, s


def elgamal_verify(message, signature, public_key):
    r, s = signature
    p = EL_P

    if not (0 < r < p and 0 <= s < p - 1):
        return False

    z = hash_value(message) % (p - 1)

    left = pow(EL_ALPHA, z, p)

    right = (
        pow(public_key, r, p) *
        pow(r, s, p)
    ) % p

    return left == right


def elgamal_experiment():
    print("\nEXPERIMENT 4: ELGAMAL SIGNATURE")
    print("=" * 65)

    message = "ElGamal Secure Message"

    signature = elgamal_sign(
        message,
        EL_PRIVATE,
        5
    )

    print("Prime p:", EL_P)
    print("Generator alpha:", EL_ALPHA)
    print("Private Key:", EL_PRIVATE)
    print("Public Key:", EL_PUBLIC)

    print("\nMessage:", message)
    print("Signature (r, s):", signature)

    print("\nValid Signature:",
          elgamal_verify(message, signature, EL_PUBLIC))

    print("Modified Message:",
          elgamal_verify("Changed Message", signature, EL_PUBLIC))

    modified_signature = (
        signature[0],
        (signature[1] + 1) % (EL_P - 1)
    )

    print("Modified Signature:",
          elgamal_verify(message, modified_signature, EL_PUBLIC))


# ==================================================
# EXPERIMENT 5: SCHNORR SIGNATURE
# ==================================================

SCH_P = 23
SCH_Q = 11
SCH_G = 2

SCH_PRIVATE = 3
SCH_PUBLIC = pow(SCH_G, SCH_PRIVATE, SCH_P)


def schnorr_sign(message, private_key, nonce):
    commitment = pow(SCH_G, nonce, SCH_P)

    challenge = hash_value(
        str(commitment) + message
    ) % SCH_Q

    response = (
        nonce + challenge * private_key
    ) % SCH_Q

    return commitment, challenge, response


def schnorr_verify(message, signature, public_key):
    commitment, challenge, response = signature

    if not (
        0 < commitment < SCH_P
        and 0 <= challenge < SCH_Q
        and 0 <= response < SCH_Q
    ):
        return False

    expected = hash_value(
        str(commitment) + message
    ) % SCH_Q

    if challenge != expected:
        return False

    left = pow(SCH_G, response, SCH_P)

    right = (
        commitment *
        pow(public_key, challenge, SCH_P)
    ) % SCH_P

    return left == right


def schnorr_experiment():
    print("\nEXPERIMENT 5: SCHNORR SIGNATURE")
    print("=" * 65)

    message = "Schnorr Authentication Message"

    signature = schnorr_sign(
        message,
        SCH_PRIVATE,
        7
    )

    print("Prime p:", SCH_P)
    print("Prime q:", SCH_Q)
    print("Generator g:", SCH_G)

    print("Private Key:", SCH_PRIVATE)
    print("Public Key:", SCH_PUBLIC)

    print("\nMessage:", message)

    print("Signature (Commitment, Challenge, Response):",
          signature)

    print("Valid Signature:",
          schnorr_verify(message, signature, SCH_PUBLIC))

    print("Modified Message:",
          schnorr_verify("Changed Message", signature, SCH_PUBLIC))


# ==================================================
# EXPERIMENT 6: ELGAMAL NONCE REUSE
# ==================================================

def nonce_reuse_experiment():
    print("\nEXPERIMENT 6: ELGAMAL NONCE REUSE")
    print("=" * 65)

    message1 = "Payment Rs.1000"
    message2 = "Payment Rs.5000"

    nonce = 5

    signature1 = elgamal_sign(
        message1,
        EL_PRIVATE,
        nonce
    )

    signature2 = elgamal_sign(
        message2,
        EL_PRIVATE,
        nonce
    )

    print("Message 1:", message1)
    print("Message 2:", message2)

    print("Signature 1:", signature1)
    print("Signature 2:", signature2)

    print("\nNonce Reused:", nonce)

    print("First r value:", signature1[0])
    print("Second r value:", signature2[0])

    print("Same r value:",
          signature1[0] == signature2[0])

    print("\nObservation: Reusing a signing nonce exposes")
    print("relationships that can enable private-key recovery.")
    print("A unique, unpredictable nonce is essential.")


# ==================================================
# EXPERIMENT 7: COLLISION-BASED SIGNATURE FORGERY
# ==================================================

def collision_forgery_experiment():
    print("\nEXPERIMENT 7: COLLISION-BASED SIGNATURE FORGERY")
    print("=" * 65)

    seen = {}
    collision = None

    for i in range(100000):
        message = "Message_" + str(i)

        digest = truncated_hash(message, 16)

        if digest in seen and seen[digest] != message:
            collision = (seen[digest], message, digest)
            break

        seen[digest] = message

    if collision is None:
        print("No collision found within the search limit.")
        return

    message1, message2, digest = collision

    print("Message 1:", message1)
    print("Message 2:", message2)
    print("Truncated Hash:", digest)

    print("Collision Found:",
          truncated_hash(message1, 16) ==
          truncated_hash(message2, 16))

    public_key, private_key = rsa_key_generation()

    e, n = public_key
    d, n = private_key

    signature = pow(digest, d, n)

    verification1 = pow(signature, e, n)
    verification2 = pow(signature, e, n)

    print("\nSignature of Message 1:", signature)

    print("Verification for Message 1:",
          verification1 == digest)

    print("Verification for Message 2:",
          verification2 == truncated_hash(message2, 16))

    print("\nCollision-Based Forgery Successful:",
          verification1 == truncated_hash(message2, 16))


# ==================================================
# EXPERIMENT 8: KERBEROS AND X.509 COMPARISON
# ==================================================

def framework_comparison():
    print("\nEXPERIMENT 8: KERBEROS VS X.509")
    print("=" * 90)

    print(f"{'Feature':<25} {'Kerberos':<30} {'X.509 / PKI':<30}")
    print("-" * 90)

    rows = [
        ("Key Type", "Symmetric keys", "Public and private keys"),
        ("Trusted Third Party", "KDC", "Certificate Authority"),
        ("Online Dependence", "KDC needed for ticket issue", "Certificate checks can be offline"),
        ("Scalability", "Central KDC", "Distributed certificate hierarchy"),
        ("Revocation", "Ticket/key management", "CRL and OCSP"),
        ("Typical Environment", "Enterprise SSO", "Web, TLS and digital signing"),
        ("Non-Repudiation", "Not normally provided", "Can support non-repudiation")
    ]

    for row in rows:
        print(f"{row[0]:<25} {row[1]:<30} {row[2]:<30}")

    print("\nKEY RELATIONSHIP COMPARISON")

    n = 100

    pairwise = n * (n - 1) // 2

    print("Number of users:", n)

    print("Pairwise Shared Keys:", pairwise)

    print("Kerberos Client-KDC Keys:", n)

    print("PKI User Key Pairs:", n)

    print("\nRECOMMENDATIONS")

    print("Campus Single Sign-On: Kerberos")

    print("Legally Binding Electronic Contracts: X.509 / PKI")


# ==================================================
# MAIN PROGRAM
# ==================================================

if __name__ == "__main__":

    print("ADVANCED DIGITAL SIGNATURE ANALYSIS")
    print("=" * 65)

    rsa_experiment()

    dsa_experiment()

    ecdsa_experiment()

    elgamal_experiment()

    schnorr_experiment()

    nonce_reuse_experiment()

    collision_forgery_experiment()

    framework_comparison()

    print("\nALL Q6 EXPERIMENTS COMPLETED")
