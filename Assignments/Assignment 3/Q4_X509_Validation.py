
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta
import hashlib


# KEY GENERATION

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


# CERTIFICATE NAME

def create_name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])


# CERTIFICATE GENERATION

def create_certificate(
    subject,
    issuer,
    subject_key,
    issuer_key,
    is_ca,
    not_before,
    not_after,
    hostname=None,
    key_cert_sign=None
):
    builder = x509.CertificateBuilder()

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    builder = builder.add_extension(
        x509.BasicConstraints(
            ca=is_ca,
            path_length=1 if is_ca else None
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=not is_ca,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=is_ca if key_cert_sign is None else key_cert_sign,
            crl_sign=is_ca if key_cert_sign is None else key_cert_sign,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    if hostname:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname)
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )

    return builder.sign(issuer_key, hashes.SHA256())


# CERTIFICATE SIGNATURE VERIFICATION

def verify_signature(certificate, issuer_key):
    issuer_key.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm
    )


# CERTIFICATE VALIDITY CHECK

def check_validity(certificate):
    now = datetime.utcnow()

    if now < certificate.not_valid_before:
        raise ValueError("Certificate is not yet valid")

    if now > certificate.not_valid_after:
        raise ValueError("Certificate has expired")


# CHAIN VALIDATION

def validate_chain(leaf, intermediate, root, hostname, crl=None):

    # ROOT TRUST CHECK
    if root.fingerprint(hashes.SHA256()) != ROOT_FINGERPRINT:
        raise ValueError("Untrusted root certificate")

    # ROOT SELF-SIGNATURE
    if root.issuer != root.subject:
        raise ValueError("Root issuer mismatch")

    verify_signature(root, root.public_key())
    check_validity(root)

    # INTERMEDIATE ISSUER CHECK
    if intermediate.issuer != root.subject:
        raise ValueError("Intermediate issuer mismatch")

    verify_signature(intermediate, root.public_key())
    check_validity(intermediate)

    # INTERMEDIATE CA CHECK
    constraints = intermediate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    if not constraints.ca:
        raise ValueError("Intermediate certificate is not a CA")

    usage = intermediate.extensions.get_extension_for_class(
        x509.KeyUsage
    ).value

    if not usage.key_cert_sign:
        raise ValueError("Intermediate cannot sign certificates")

    # LEAF ISSUER CHECK
    if leaf.issuer != intermediate.subject:
        raise ValueError("Leaf issuer mismatch")

    verify_signature(leaf, intermediate.public_key())
    check_validity(leaf)

    # LEAF CA CHECK
    leaf_constraints = leaf.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value

    if leaf_constraints.ca:
        raise ValueError("Unexpected CA certificate")

    # HOSTNAME CHECK
    san = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    if hostname not in san.get_values_for_type(x509.DNSName):
        raise ValueError("Hostname mismatch")

    # REVOCATION CHECK
    if crl is not None:

        if crl.issuer != intermediate.subject:
            raise ValueError("CRL issuer mismatch")

        verify_signature(crl, intermediate.public_key())

        now = datetime.utcnow()

        if now < crl.last_update or now > crl.next_update:
            raise ValueError("CRL is not currently valid")

        for revoked in crl:
            if revoked.serial_number == leaf.serial_number:
                raise ValueError("Certificate has been revoked")

    return True


# CREATE CERTIFICATE HIERARCHY

now = datetime.utcnow()

root_key = generate_key()
intermediate_key = generate_key()
leaf_key = generate_key()

root_name = create_name("SIMATS Root CA")
intermediate_name = create_name("SIMATS Intermediate CA")
leaf_name = create_name("www.example.com")

root = create_certificate(
    root_name,
    root_name,
    root_key,
    root_key,
    True,
    now - timedelta(days=365),
    now + timedelta(days=3650)
)

ROOT_FINGERPRINT = root.fingerprint(hashes.SHA256())

intermediate = create_certificate(
    intermediate_name,
    root_name,
    intermediate_key,
    root_key,
    True,
    now - timedelta(days=30),
    now + timedelta(days=365)
)

leaf = create_certificate(
    leaf_name,
    intermediate_name,
    leaf_key,
    intermediate_key,
    False,
    now - timedelta(days=10),
    now + timedelta(days=90),
    hostname="www.example.com"
)


# CREATE WRONG ISSUER CERTIFICATE

wrong_key = generate_key()
wrong_name = create_name("Wrong Certificate Authority")

wrong_intermediate = create_certificate(
    wrong_name,
    wrong_name,
    wrong_key,
    wrong_key,
    True,
    now - timedelta(days=10),
    now + timedelta(days=365)
)


# CREATE EXPIRED CERTIFICATE

expired_leaf = create_certificate(
    leaf_name,
    intermediate_name,
    leaf_key,
    intermediate_key,
    False,
    now - timedelta(days=10),
    now - timedelta(days=1),
    hostname="www.example.com"
)


# CREATE NOT-YET-VALID CERTIFICATE

future_leaf = create_certificate(
    leaf_name,
    intermediate_name,
    leaf_key,
    intermediate_key,
    False,
    now + timedelta(days=5),
    now + timedelta(days=90),
    hostname="www.example.com"
)


# CREATE HOSTNAME MISMATCH CERTIFICATE

wrong_host_leaf = create_certificate(
    leaf_name,
    intermediate_name,
    leaf_key,
    intermediate_key,
    False,
    now - timedelta(days=10),
    now + timedelta(days=90),
    hostname="wrong.example.com"
)


# CREATE NON-CA INTERMEDIATE

non_ca_key = generate_key()
non_ca_name = create_name("SIMATS Non-CA Certificate")

non_ca_intermediate = create_certificate(
    non_ca_name,
    root_name,
    non_ca_key,
    root_key,
    False,
    now - timedelta(days=10),
    now + timedelta(days=365),
    key_cert_sign=False
)

non_ca_leaf = create_certificate(
    leaf_name,
    non_ca_name,
    leaf_key,
    non_ca_key,
    False,
    now - timedelta(days=10),
    now + timedelta(days=90),
    hostname="www.example.com"
)


# CREATE REVOCATION LIST

revoked_certificate = x509.RevokedCertificateBuilder().serial_number(
    leaf.serial_number
).revocation_date(
    now - timedelta(minutes=1)
).build()

crl = x509.CertificateRevocationListBuilder().issuer_name(
    intermediate_name
).last_update(
    now - timedelta(minutes=1)
).next_update(
    now + timedelta(days=1)
).add_revoked_certificate(
    revoked_certificate
).sign(
    intermediate_key,
    hashes.SHA256()
)


# TESTING FUNCTION

def run_test(description, leaf_cert, intermediate_cert,
             root_cert, hostname, revocation_list=None):

    print("\nTest:", description)

    try:
        result = validate_chain(
            leaf_cert,
            intermediate_cert,
            root_cert,
            hostname,
            revocation_list
        )

        print("Result: ACCEPTED")

    except Exception as error:
        print("Result: REJECTED")
        print("Reason:", error)


# EXPERIMENT 1: VALID CERTIFICATE CHAIN

def valid_chain_test():
    print("\nEXPERIMENT 1: VALID CERTIFICATE CHAIN")
    print("=" * 65)

    print("Root CA:", root.subject.rfc4514_string())
    print("Intermediate CA:", intermediate.subject.rfc4514_string())
    print("End Entity:", leaf.subject.rfc4514_string())

    print("\nCertificate Chain:")
    print("Root CA -> Intermediate CA -> End Entity")

    run_test(
        "Valid Certificate Chain",
        leaf,
        intermediate,
        root,
        "www.example.com"
    )


# EXPERIMENT 2: FAILURE CASES

def failure_tests():
    print("\nEXPERIMENT 2: INVALID CERTIFICATE TESTS")
    print("=" * 65)

    run_test(
        "Expired Certificate",
        expired_leaf,
        intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "Not-Yet-Valid Certificate",
        future_leaf,
        intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "Wrong Issuer",
        leaf,
        wrong_intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "Hostname Mismatch",
        wrong_host_leaf,
        intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "End Entity Used as CA",
        non_ca_leaf,
        non_ca_intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "Revoked Certificate",
        leaf,
        intermediate,
        root,
        "www.example.com",
        crl
    )


# EXPERIMENT 3: TAMPERED CERTIFICATE

def tampered_certificate_test():
    print("\nEXPERIMENT 3: TAMPERED CERTIFICATE")
    print("=" * 65)

    certificate_data = leaf.public_bytes(
        serialization.Encoding.DER
    )

    tampered_data = (
        certificate_data[:-1] +
        bytes([certificate_data[-1] ^ 1])
    )

    try:
        tampered_certificate = x509.load_der_x509_certificate(
            tampered_data
        )

        verify_signature(
            tampered_certificate,
            intermediate_key.public_key()
        )

        print("Result: ACCEPTED")

    except Exception:
        print("Result: REJECTED")
        print("Reason: Certificate signature verification failed")


# EXPERIMENT 4: CRL COMPARISON

def crl_experiment():
    print("\nEXPERIMENT 4: CRL REVOCATION CHECK")
    print("=" * 65)

    run_test(
        "Revoked Certificate Without CRL Checking",
        leaf,
        intermediate,
        root,
        "www.example.com"
    )

    run_test(
        "Revoked Certificate With CRL Checking",
        leaf,
        intermediate,
        root,
        "www.example.com",
        crl
    )

    print("\nCRL contains revoked serial number:",
          leaf.serial_number in [
              item.serial_number for item in crl
          ])


# CERTIFICATE DETAILS

def certificate_details():
    print("\nEXPERIMENT 5: X.509 CERTIFICATE DETAILS")
    print("=" * 65)

    print("Certificate Subject:", leaf.subject.rfc4514_string())
    print("Certificate Issuer:", leaf.issuer.rfc4514_string())
    print("Serial Number:", leaf.serial_number)

    print("Valid From:", leaf.not_valid_before)
    print("Valid Until:", leaf.not_valid_after)

    print("Signature Algorithm:",
          leaf.signature_hash_algorithm.name)

    print("Public Key Type:",
          type(leaf.public_key()).__name__)

    print("SHA-256 Fingerprint:",
          hashlib.sha256(
              leaf.public_bytes(serialization.Encoding.DER)
          ).hexdigest())


# MAIN PROGRAM

if __name__ == "__main__":

    print("X.509 CERTIFICATE CHAIN VALIDATION")
    print("=" * 65)

    valid_chain_test()

    failure_tests()

    tampered_certificate_test()

    crl_experiment()

    certificate_details()

    print("\nALL X.509 EXPERIMENTS COMPLETED")
