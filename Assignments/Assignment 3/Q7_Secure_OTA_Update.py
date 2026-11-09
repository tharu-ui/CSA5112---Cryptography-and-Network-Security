
import hashlib
import json
import copy
import time


# ==================================================
# RSA KEY GENERATION - EDUCATIONAL TOY PARAMETERS
# ==================================================

def generate_rsa_keys(p, q, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


MANUFACTURER_PUBLIC, MANUFACTURER_PRIVATE = generate_rsa_keys(1009, 1013)

WRONG_PUBLIC, WRONG_PRIVATE = generate_rsa_keys(1013, 1019)

TRUSTED_KEYS = {
    "MANUFACTURER-KEY-01": MANUFACTURER_PUBLIC
}

REVOKED_KEYS = set()

DEVICE_MODEL = "INFUSION-PUMP-X1"


# ==================================================
# HASHING AND SIGNATURE FUNCTIONS
# ==================================================

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_manifest(manifest):
    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


def sign_manifest(manifest, private_key):
    d, n = private_key

    manifest_bytes = canonical_manifest(manifest)

    digest = int.from_bytes(
        hashlib.sha256(manifest_bytes).digest(),
        "big"
    )

    return pow(digest % n, d, n)


def verify_signature(manifest, signature, public_key):
    e, n = public_key

    manifest_bytes = canonical_manifest(manifest)

    digest = int.from_bytes(
        hashlib.sha256(manifest_bytes).digest(),
        "big"
    )

    recovered = pow(signature, e, n)

    return recovered == digest % n


# ==================================================
# MANIFEST CREATION
# ==================================================

def create_manifest(firmware, version, key_id):
    return {
        "device_model": DEVICE_MODEL,
        "version": version,
        "release_counter": version,
        "firmware_sha256": sha256(firmware),
        "key_id": key_id,
        "certificate_not_before": 1000,
        "certificate_not_after": 9999999999
    }


# ==================================================
# SECURE UPDATE VERIFICATION
# ==================================================

def verify_update(
    firmware,
    manifest,
    signature,
    installed_version,
    device_model,
    trusted_time=None
):
    hash_operations = 0
    signature_verifications = 0

    if device_model != manifest["device_model"]:
        return False, "Device model mismatch", hash_operations, signature_verifications

    if manifest["version"] <= installed_version:
        return False, "Rollback or duplicate version rejected", hash_operations, signature_verifications

    key_id = manifest["key_id"]

    if key_id in REVOKED_KEYS:
        return False, "Signing key has been revoked", hash_operations, signature_verifications

    if key_id not in TRUSTED_KEYS:
        return False, "Unknown signing key", hash_operations, signature_verifications

    if trusted_time is not None:
        if trusted_time < manifest["certificate_not_before"]:
            return False, "Certificate is not yet valid", hash_operations, signature_verifications

        if trusted_time > manifest["certificate_not_after"]:
            return False, "Certificate has expired", hash_operations, signature_verifications

    actual_hash = sha256(firmware)
    hash_operations += 1

    if actual_hash != manifest["firmware_sha256"]:
        return False, "Firmware integrity check failed", hash_operations, signature_verifications

    signature_verifications += 1

    if not verify_signature(
        manifest,
        signature,
        TRUSTED_KEYS[key_id]
    ):
        return False, "Digital signature verification failed", hash_operations, signature_verifications

    return True, "Update accepted", hash_operations, signature_verifications


# ==================================================
# BASELINE: UNSIGNED SHA-256 HASH
# ==================================================

def baseline_verify(firmware, published_hash):
    return sha256(firmware) == published_hash


# ==================================================
# TEST CASES
# ==================================================

def run_test(name, firmware, manifest, signature, installed_version=1,
             device_model=DEVICE_MODEL, trusted_time=None):

    accepted, reason, hashes, signatures = verify_update(
        firmware,
        manifest,
        signature,
        installed_version,
        device_model,
        trusted_time
    )

    print("\n" + name)
    print("Result:", "ACCEPTED" if accepted else "REJECTED")
    print("Reason:", reason)
    print("Hash operations:", hashes)
    print("Signature verifications:", signatures)

    return accepted


# ==================================================
# MAIN EXPERIMENT
# ==================================================

def main():

    print("=" * 65)
    print("SECURE OTA FIRMWARE UPDATE - EXPERIMENT")
    print("=" * 65)

    firmware = b"INFUSION PUMP FIRMWARE VERSION 2 - SECURE RELEASE"

    manifest = create_manifest(
        firmware,
        2,
        "MANUFACTURER-KEY-01"
    )

    signature = sign_manifest(
        manifest,
        MANUFACTURER_PRIVATE
    )

    print("\nFIRMWARE DETAILS")
    print("Device Model:", DEVICE_MODEL)
    print("Installed Version: 1")
    print("New Version:", manifest["version"])
    print("SHA-256:", manifest["firmware_sha256"])
    print("Signing Key:", manifest["key_id"])

    metadata_size = (
        len(canonical_manifest(manifest)) +
        len(str(signature).encode())
    )

    print("Added Metadata Size:", metadata_size, "bytes")

    # TEST 1: VALID UPDATE

    run_test(
        "TEST 1: VALID FIRMWARE UPDATE",
        firmware,
        manifest,
        signature
    )

    # TEST 2: MODIFIED FIRMWARE

    modified_firmware = firmware + b" MALICIOUS CODE"

    run_test(
        "TEST 2: MODIFIED FIRMWARE",
        modified_firmware,
        manifest,
        signature
    )

    # TEST 3: MODIFIED SIGNATURE

    modified_signature = signature + 1

    run_test(
        "TEST 3: MODIFIED SIGNATURE",
        firmware,
        manifest,
        modified_signature
    )

    # TEST 4: ROLLBACK ATTACK

    run_test(
        "TEST 4: REPLAYED OLDER VERSION",
        firmware,
        manifest,
        signature,
        installed_version=2
    )

    # TEST 5: REVOKED SIGNING KEY

    REVOKED_KEYS.add("MANUFACTURER-KEY-01")

    run_test(
        "TEST 5: REVOKED SIGNING KEY",
        firmware,
        manifest,
        signature
    )

    REVOKED_KEYS.clear()

    # TEST 6: UNKNOWN / WRONG KEY

    wrong_manifest = copy.deepcopy(manifest)

    wrong_signature = sign_manifest(
        wrong_manifest,
        WRONG_PRIVATE
    )

    run_test(
        "TEST 6: SIGNATURE CREATED WITH WRONG PRIVATE KEY",
        firmware,
        wrong_manifest,
        wrong_signature
    )

    # TEST 7: EXPIRED CERTIFICATE

    expired_manifest = copy.deepcopy(manifest)

    expired_manifest["certificate_not_after"] = 1500

    expired_signature = sign_manifest(
        expired_manifest,
        MANUFACTURER_PRIVATE
    )

    run_test(
        "TEST 7: EXPIRED CERTIFICATE",
        firmware,
        expired_manifest,
        expired_signature,
        trusted_time=2000
    )

    # TEST 8: WRONG DEVICE MODEL

    run_test(
        "TEST 8: WRONG DEVICE MODEL",
        firmware,
        manifest,
        signature,
        device_model="OTHER-PUMP"
    )

    # TEST 9: OFFLINE DEVICE WITH NO TRUSTED CLOCK

    run_test(
        "TEST 9: OFFLINE DEVICE - CLOCK UNAVAILABLE",
        firmware,
        manifest,
        signature,
        trusted_time=None
    )

    # TEST 10: BASELINE HASH ATTACK

    print("\nTEST 10: BASELINE UNSIGNED HASH ATTACK")

    original_hash = sha256(firmware)

    attacker_firmware = b"ATTACKER MODIFIED FIRMWARE"

    attacker_published_hash = sha256(attacker_firmware)

    print("Original Firmware Hash:", original_hash)
    print("Attacker's Published Hash:", attacker_published_hash)

    print("Baseline Accepts Modified Firmware:",
          baseline_verify(
              attacker_firmware,
              attacker_published_hash
          ))

    print("Observation: An attacker can replace both the firmware")
    print("and its unsigned published hash.")

    # SUMMARY

    print("\n" + "=" * 65)
    print("EXPERIMENT SUMMARY")
    print("=" * 65)

    print("Firmware Integrity: SHA-256")
    print("Firmware Authentication: RSA Digital Signature")
    print("Rollback Protection: Monotonic Version Counter")
    print("Key Revocation: Trusted Revocation Information")
    print("Device Authentication: Device Identity / Certificate")
    print("Offline Handling: Pinned Trust and Local Security State")

    print("\nALL OTA SECURITY TESTS COMPLETED")


if __name__ == "__main__":
    main()
