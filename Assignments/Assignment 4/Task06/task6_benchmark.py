import json
import base64
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent
STORE_FILE = BASE_DIR / "keystore.json"


def load_valid_public_keys():
    recipients = json.loads(STORE_FILE.read_text())
    public_keys = []

    for recipient in recipients:
        if recipient["email"] not in (
            "alice@example.com",
            "bob@example.com",
            "carol@example.com"
        ):
            continue

        path = BASE_DIR / recipient["public_key_file"]

        with path.open("rb") as file:
            public_key = serialization.load_pem_public_key(file.read())

        public_keys.append(public_key)

    return public_keys


def benchmark():
    public_keys = load_valid_public_keys()

    if len(public_keys) != 3:
        raise RuntimeError(
            "Expected Alice, Bob and Carol public keys. "
            "Run task6_secure_mailing.py first."
        )

    message = b"Secure company newsletter. " * 40

    print("\nTASK 6: COST GROWTH BENCHMARK")
    print("=" * 78)
    print("Scaling test uses the existing three valid public keys cyclically.")
    print("This is a performance model, not a production recipient key store.\n")

    print(
        f"{'Recipients':>10} | {'Public-key ops':>14} | "
        f"{'Symmetric ops':>13} | {'Size (bytes)':>12} | {'Time (ms)':>10}"
    )
    print("-" * 78)

    rows = []

    for count in (1, 10, 100, 1000):
        start = time.perf_counter()

        # One session key and one message encryption.
        session_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        ciphertext = AESGCM(session_key).encrypt(
            nonce, message, None
        )

        wrapped_keys = {}

        # One RSA wrapping operation for every simulated recipient.
        for index in range(count):
            public_key = public_keys[index % len(public_keys)]

            wrapped = public_key.encrypt(
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

        rows.append({
            "recipients": count,
            "public_key_operations": count,
            "symmetric_encryption_operations": 1,
            "message_size_bytes": package_size,
            "execution_time_ms": round(elapsed_ms, 2)
        })

        print(
            f"{count:10} | {count:14} | {1:13} | "
            f"{package_size:12} | {elapsed_ms:10.2f}"
        )

    output_file = BASE_DIR / "task6_growth_results.csv"

    with output_file.open("w", newline="") as file:
        import csv

        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("\nBenchmark results saved to task6_growth_results.csv")


if __name__ == "__main__":
    benchmark()
