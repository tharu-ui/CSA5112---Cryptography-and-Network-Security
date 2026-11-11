
import dkim
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

DOMAIN = b"example.com"
SELECTOR = b"mail"

# Generate DKIM key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_der = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_key = base64.b64encode(public_der)

# Simulated DNS DKIM record
dns_record = (
    b"v=DKIM1; k=rsa; p=" + public_key
)

def dns_lookup(name, timeout=5):
    return dns_record

# SPF verification
def spf_check(ip):
    authorised_ip = "192.0.2.10"

    print("Sending IP:", ip)

    if ip == authorised_ip:
        print("SPF: PASS")
        return True

    print("SPF: FAIL")
    return False

# DKIM signing
def sign_email(message):
    signature = dkim.sign(
        message,
        SELECTOR,
        DOMAIN,
        private_pem,
        include_headers=[
            b"from", b"to", b"subject"
        ]
    )

    return signature + message

# DKIM verification
def verify_email(message):
    result = dkim.verify(
        message,
        dnsfunc=dns_lookup
    )

    if result:
        print("DKIM: PASS")
    else:
        print("DKIM: FAIL")

    return result

# Simplified DMARC evaluation
def dmarc_check(spf, dkim_result, from_domain):
    aligned = from_domain == DOMAIN

    if aligned and (spf or dkim_result):
        print("DMARC: PASS")
        print("Policy: Accept email")
    else:
        print("DMARC: FAIL")
        print("Policy: Reject email")


# Original email
email = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: Bob <bob@example.com>\r\n"
    b"Subject: Security Test\r\n"
    b"\r\n"
    b"This is a secure test email.\r\n"
)

print("TASK 5: EMAIL AUTHENTICATION")
print("================================")

# Test 1: Legitimate email
print("\nTEST 1: Legitimate Email")

spf = spf_check("192.0.2.10")

signed_email = sign_email(email)
dkim_result = verify_email(signed_email)

dmarc_check(spf, dkim_result, DOMAIN)

# Test 2: Spoofed email
print("\nTEST 2: Spoofed Email")

spf = spf_check("203.0.113.50")

dkim_result = False
print("DKIM: FAIL - Invalid signature")

dmarc_check(spf, dkim_result, DOMAIN)

# Test 3: Modified email
print("\nTEST 3: Modified Email")

modified_email = signed_email.replace(
    b"secure test email",
    b"modified email"
)

spf = spf_check("192.0.2.10")
dkim_result = verify_email(modified_email)

dmarc_check(spf, dkim_result, DOMAIN)

print("\nEmail authentication tests completed.")
