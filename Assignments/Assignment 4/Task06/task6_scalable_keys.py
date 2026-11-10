import datetime

class KeyRecord:
    def __init__(self, recipient, is_valid, expired, revoked):
        self.recipient = recipient
        self.is_valid = is_valid
        self.expired = expired
        self.revoked = revoked

class ScalableMailEngine:
    def __init__(self):
        self.key_store = {}

    def add_key(self, recipient, record):
        self.key_store[recipient] = record

    def prepare_bulk_mailing(self, recipients):
        valid_count = 0
        skipped_count = 0
        print("\n[BULK MAILING ENGINE] Processing recipient key states...")
        
        for r in recipients:
            record = self.key_store.get(r)
            if not record or not record.is_valid:
                skipped_count += 1
                print(f"  - Skipped: {r} (Missing key)")
            elif record.expired:
                skipped_count += 1
                print(f"  - Skipped: {r} (Key Expired)")
            elif record.revoked:
                skipped_count += 1
                print(f"  - Skipped: {r} (Key Revoked)")
            else:
                valid_count += 1
                print(f"  - Encrypting for valid recipient: {r}")
                
        print(f"\n[SUMMARY] Recipients valid: {valid_count} | skipped: {skipped_count}")
        print(f"Public-key operations: {valid_count} | Symmetric operations: 1")

if __name__ == "__main__":
    engine = ScalableMailEngine()
    engine.add_key("Dr. Rao", KeyRecord("Dr. Rao", True, False, False))
    engine.add_key("Dr. Smith", KeyRecord("Dr. Smith", True, True, False)) # Expired
    engine.add_key("Dr. Jones", KeyRecord("Dr. Jones", True, False, True)) # Revoked
    engine.add_key("Dr. Lee", KeyRecord("Dr. Lee", True, False, False))

    engine.prepare_bulk_mailing(["Dr. Rao", "Dr. Smith", "Dr. Jones", "Dr. Lee"])