class DmracEngine:
    def evaluate_email(self, mail_from, dkim_domain, dmarc_policy):
        print(f"\n[DMARC CHECK] From: {mail_from} | DKIM Signed Domain: {dkim_domain} | Policy: {dmarc_policy}")
        
        spf_aligned = mail_from.split('@')[-1] == "hospital.com"
        dkim_aligned = dkim_domain == "hospital.com"
        
        if spf_aligned or dkim_aligned:
            print("[PASS] DMARC alignment successful. Email authenticated.")
            return "PASS"
        else:
            if dmarc_policy == "reject":
                print("[FAIL & REJECT] DMARC alignment failed. Message dropped.")
                return "REJECT"
            elif dmarc_policy == "quarantine":
                print("[FAIL & QUARANTINE] DMARC alignment failed. Sent to spam folder.")
                return "QUARANTINE"
            else:
                print("[NONE] Alignment failed, but policy set to none.")
                return "NONE"

if __name__ == "__main__":
    engine = DmracEngine()
    engine.evaluate_email("attacker@evil.com", "evil.com", "reject")
    engine.evaluate_email("admin@hospital.com", "hospital.com", "reject")