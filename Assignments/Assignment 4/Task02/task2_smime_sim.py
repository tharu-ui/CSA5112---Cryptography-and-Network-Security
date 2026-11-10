import datetime

class Certificate:
    def __init__(self, subject, issuer, is_ca, not_before, not_after, revoked=False):
        self.subject = subject
        self.issuer = issuer
        self.is_ca = is_ca
        self.not_before = not_before
        self.not_after = not_after
        self.revoked = revoked

def validate_smime_certificate(cert, issuer_cert, trusted_root, current_time, sender_email):
    print(f"\n[S/MIME VALIDATION] Verifying certificate for: {cert.subject}")
    
    # 1. Check validity period
    if not (cert.not_before <= current_time <= cert.not_after):
        print("[FAIL] Certificate is expired or not yet valid.")
        return False
        
    # 2. Check revocation status
    if cert.revoked:
        print("[FAIL] Certificate has been revoked in CRL.")
        return False

    # 3. Check Issuer Signature / Trust Chain
    if cert.issuer != issuer_cert.subject:
        print("[FAIL] Issuer DN does not match signer subject.")
        return False
        
    if issuer_cert.issuer != trusted_root.subject:
        print("[FAIL] Chain does not terminate at a Trusted Root CA.")
        return False

    # 4. Check Subject-to-Sender Match
    if cert.subject != sender_email:
        print(f"[FAIL] Email mismatch: Certificate subject '{cert.subject}' does not match sender '{sender_email}'.")
        return False

    print("[SUCCESS] Certificate chain and sender identity fully verified.")
    return True

if __name__ == "__main__":
    now = datetime.datetime(2026, 6, 1)
    root = Certificate("RootCA", "RootCA", True, datetime.datetime(2020,1,1), datetime.datetime(2030,1,1))
    inter = Certificate("HospitalInterCA", "RootCA", True, datetime.datetime(2023,1,1), datetime.datetime(2028,1,1))
    user_cert = Certificate("doctor@hospital.com", "HospitalInterCA", False, datetime.datetime(2025,1,1), datetime.datetime(2027,1,1), revoked=False)

    # Normal test case
    validate_smime_certificate(user_cert, inter, root, now, "doctor@hospital.com")

    # Failure test case: Expired certificate
    expired_cert = Certificate("doctor@hospital.com", "HospitalInterCA", False, datetime.datetime(2020,1,1), datetime.datetime(2021,1,1))
    validate_smime_certificate(expired_cert, inter, root, now, "doctor@hospital.com")