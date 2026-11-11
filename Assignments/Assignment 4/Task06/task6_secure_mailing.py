
import os
import json
import base64
import hashlib
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public_keys"
PRIVATE_DIR = BASE_DIR / "private_keys"
STORE_FILE = BASE_DIR / "keystore.json"

for folder in (PUBLIC_DIR, PRIVATE_DIR):
    folder.mkdir(exist_ok=True)

# Keep private keys out of Git.
gitignore = BASE_DIR / ".gitignore"
ignore_line = "private_keys/\n"
if not gitignore.exists():
    gitignore.write_text(ignore_line)
elif "private_keys/" not in gitignore.read_text():
    with gitignore.open("a") as file:
        file.write(ignore_line)


# --------------------------------------------------
# KEY GENERATION AND KEY STORE
# --------------------------------------------------

def fingerprint(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).hexdigest()


def create_recipient(name, email, state="valid"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_path = PRIVATE_DIR / f"{name}_private.pem"
    public_path = PUBLIC_DIR / f"{name}_public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Restrict private-key file permissions where supported.
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    now = datetime.now(timezone.utc)

    valid_from = now - timedelta(days=30)
    valid_until = now + timedelta(days=365)
    revoked = False
    trust_level = "trusted"
    public_file = str(public_path.relative_to(BASE_DIR))

    if state == "expired":
        valid_until = now - timedelta(days=1)
    elif state == "revoked":
        revoked = True
    elif state == "untrusted":
        trust_level = "untrusted"

    return {
        "name": name,
        "email": email,
        "public_key_file": public_file,
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat(),
        "revoked": revoked,
        "trust_level": trust_level,
        "fingerprint": fingerprint(public_key)
    }


def create_key_store():
    recipients = [
        create_recipient("alice", "alice@example.com", "valid"),
        create_recipient("bob", "bob@example.com", "valid"),
        create_recipient("carol", "carol@example.com", "valid"),
        create_recipient("dave", "dave@example.com", "expired"),
        create_recipient("erin", "erin@example.com", "revoked"),
        create_recipient("frank", "frank@example.com", "untrusted"),
        {
            "name": "grace",
            "email": "grace@example.com",
            "public_key_file": "public_keys/grace_missing.pem",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": (
                datetime.now(timezone.utc) + timedelta(days=365)
            ).isoformat(),
            "revoked": False,
            "trust_level": "trusted",
            "fingerprint": "NOT_AVAILABLE"
        }
    ]

    STORE_FILE.write_text(json.dumps(recipients, indent=4))
    print("Key store created:", STORE_FILE.name)
    return recipients


def load_public_key(record):
    path = BASE_DIR / record["public_key_file"]
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(name):
    path = PRIVATE_DIR / f"{name}_private.pem"
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None
    )


# --------------------------------------------------
# KEY VALIDATION
# --------------------------------------------------

def key_status(record):
    public_path = BASE_DIR / record["public_key_file"]

    if not public_path.exists():
        return "MISSING PUBLIC KEY"

    if record["revoked"]:
        return "REVOKED"

    now = datetime.now(timezone.utc)
    valid_from = datetime.fromisoformat(record["valid_from"])
    valid_until = datetime.fromisoformat(record["valid_until"])

    if now < valid_from:
        return "NOT YET VALID"

    if now > valid_until:
        return "EXPIRED"

    if record["trust_level"].lower() != "trusted":
        return "UNTRUSTED"

    return "VALID"


# --------------------------------------------------
# HYBRID ENCRYPTION ENGINE
# --------------------------------------------------

def prepare_message(recipients, message):
    print("\nRECIPIENT VALIDATION")
    print("--------------------")

    eligible = []
    skipped = []

    for recipient in recipients:
        status = key_status(recipient)

        if status == "VALID":
            eligible.append(recipient)
            print(f"{recipient['email']}: VALID")
        else:
            skipped.append((recipient, status))
            print(f"{recipient['email']}: SKIPPED - {status}")

    if not eligible:
        raise ValueError("No valid recipients. Message not encrypted.")

    # One random AES-256 session key for the message.
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    # Encrypt the message once using AES-GCM.
    ciphertext = AESGCM(session_key).encrypt(
        nonce,
        message,
        None
    )

    wrapped_keys = {}

    # Wrap the same session key separately for each valid recipient.
    for recipient in eligible:
        public_key = load_public_key(recipient)

        wrapped_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        wrapped_keys[recipient["email"]] = base64.b64encode(
            wrapped_key
        ).decode("ascii")

    package = {
        "encryption": "AES-256-GCM",
        "key_wrapping": "RSA-2048-OAEP-SHA256",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "wrapped_keys": wrapped_keys
    }

    package_bytes = json.dumps(package).encode("utf-8")

    print("\nENCRYPTION SUMMARY")
    print("------------------")
    print("Eligible recipients:", len(eligible))
    print("Skipped recipients:", len(skipped))
    print("Public-key operations:", len(eligible))
    print("Symmetric encryption operations: 1")
    print("Final message package size:", len(package_bytes), "bytes")

    return package, eligible, skipped


# --------------------------------------------------
# RECIPIENT DECRYPTION TEST
# --------------------------------------------------

def test_recipient_decryption(recipients, package):
    print("\nRECIPIENT DECRYPTION TEST")
    print("-------------------------")

    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])

    for recipient in recipients:
        email = recipient["email"]
        wrapped_text = package["wrapped_keys"].get(email)

        if wrapped_text is None:
            print(
                f"{email}: DECRYPTION DENIED - "
                f"No session-key envelope ({key_status(recipient)})"
            )
            continue

        try:
            private_key = load_private_key(recipient["name"])
            wrapped_key = base64.b64decode(wrapped_text)

            session_key = private_key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            plaintext = AESGCM(session_key).decrypt(
                nonce,
                ciphertext,
                None
            )

            print(
                f"{email}: DECRYPTION SUCCESS - "
                f"{plaintext.decode('utf-8')}"
            )

        except Exception:
            print(f"{email}: DECRYPTION FAILED")


# --------------------------------------------------
# COST GROWTH BENCHMARK
# --------------------------------------------------

def benchmark():
    print("\nCOST GROWTH BENCHMARK")
    print("---------------------")
    print("Generating 1,000 unique RSA-2048 recipient keys...")
    print("Key generation is excluded from the measured encryption time.")

    public_keys = []

    for _ in range(1000):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_keys.append(private_key.public_key())

    print("Key generation completed.")

    message = b"Secure company newsletter. " * 40

    print("\nRecipients | Public-key ops | Symmetric ops | Size (bytes) | Time (ms)")
    print("-" * 78)

    for count in (1, 10, 100, 1000):
        start = time.perf_counter()

        session_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        ciphertext = AESGCM(session_key).encrypt(
            nonce,
            message,
            None
        )

        wrapped_keys = {}

        for index in range(count):
            wrapped = public_keys[index].encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            wrapped_keys[f"recipient{index + 1}"] = (
                base64.b64encode(wrapped).decode("ascii")
            )

        package = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "wrapped_keys": wrapped_keys
        }

        package_size = len(json.dumps(package).encode("utf-8"))
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(
            f"{count:10} | "
            f"{count:14} | "
            f"{1:13} | "
            f"{package_size:12} | "
            f"{elapsed_ms:.2f}"
        )


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():
    print("=" * 55)
    print("TASK 6: SECURE MAILING AT SCALE")
    print("=" * 55)

    recipients = create_key_store()

    print("\nKEY STORE")
    print("---------")
    print("Recipient records stored in keystore.json")
    print("Public keys stored in public_keys/")
    print("Private keys stored separately in private_keys/")
    print("Private keys are excluded from Git.")

    message = (
        b"Company newsletter: Important security and service updates."
    )

    package, eligible, skipped = prepare_message(
        recipients,
        message
    )

    # Five-recipient validation:
    # Alice, Bob, Carol, Dave and Erin.
    validation_recipients = recipients[:5]

    print("\nVALIDATION WITH FIVE RECIPIENTS")
    print("-------------------------------")
    print("Expected: 3 valid, 1 expired, 1 revoked.")

    test_recipient_decryption(
        validation_recipients,
        package
    )

    print("\nADDITIONAL INVALID-KEY CHECKS")
    print("-----------------------------")
    for recipient in recipients[5:]:
        print(
            f"{recipient['email']}: "
            f"{key_status(recipient)}"
        )

    benchmark()

    print("\n" + "=" * 55)
    print("TASK 6 TESTING COMPLETED")
    print("=" * 55)


if __name__ == "__main__":
    main()
