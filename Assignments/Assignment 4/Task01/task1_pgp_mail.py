import os
import base64
import zlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PGPStyleMailEngine:
    def __init__(self):
        # Key rings storage (Simulated key store)
        self.public_key_ring = {}
        self.private_key_ring = {}

    def generate_keys(self, user_id):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        self.private_key_ring[user_id] = private_key
        self.public_key_ring[user_id] = public_key
        return public_key

    def send_mail(self, sender_id, recipient_ids, plaintext_message):
        print(f"\n[SENDER] Starting secure mail creation for sender: {sender_id}")
        
        # 1. Sign the message
        sender_priv = self.private_key_ring[sender_id]
        signature = sender_priv.sign(
            plaintext_message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Combine message and signature for compression
        signed_payload = plaintext_message.encode('utf-8') + b":::SIG:::" + signature
        
        # 2. Compress payload
        compressed_payload = zlib.compress(signed_payload)
        print(f"[SENDER] Compression: Original size = {len(signed_payload)} bytes, Compressed = {len(compressed_payload)} bytes")

        # 3. Generate Session Key (Ks) & Encrypt Payload via AES-GCM
        session_key = AESGCM.generate_key(bit_length=256)
        session_key_id = base64.b64encode(hashes.Hash(hashes.SHA256()).finalize()[:8]).decode() # Simulated ID
        aesgcm = AESGCM(session_key)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, compressed_payload, None)
        
        # 4. Encrypt session key for each recipient
        encrypted_session_keys = {}
        pub_ops = 0
        for r_id in recipient_ids:
            r_pub = self.public_key_ring[r_id]
            enc_sk = r_pub.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_session_keys[r_id] = base64.b64encode(enc_sk).decode()
            pub_ops += 1

        # 5. Package final message in Radix-64 / Base64 format
        package = {
            "session_key_id": session_key_id,
            "encrypted_session_keys": encrypted_session_keys,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        print(f"[SENDER] Package created successfully. Public-key operations: {pub_ops}, Symmetric operations: 1")
        return package

    def receive_mail(self, recipient_id, package):
        print(f"\n[RECEIVER] Processing mail for recipient: {recipient_id}")
        try:
            if recipient_id not in package["encrypted_session_keys"]:
                raise ValueError("Recipient not found in message envelope.")

            # 1. Recover session key
            enc_sk_bytes = base64.b64decode(package["encrypted_session_keys"][recipient_id])
            recipient_priv = self.private_key_ring[recipient_id]
            session_key = recipient_priv.decrypt(
                enc_sk_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 2. Decrypt payload
            aesgcm = AESGCM(session_key)
            iv = base64.b64decode(package["iv"])
            ciphertext = base64.b64decode(package["ciphertext"])
            compressed_payload = aesgcm.decrypt(iv, ciphertext, None)

            # 3. Decompress payload
            signed_payload = zlib.decompress(compressed_payload)
            message_bytes, signature = signed_payload.split(b":::SIG:::")

            # 4. Verify signature against all known public keys to find sender
            verified_sender = None
            for s_id, s_pub in self.public_key_ring.items():
                try:
                    s_pub.verify(
                        signature,
                        message_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    verified_sender = s_id
                    break
                except Exception:
                    continue

            if not verified_sender:
                raise ValueError("Signature verification failed: Invalid signature or unknown signer.")

            print(f"[RECEIVER] Success! Message: '{message_bytes.decode()}' | Verified Signer: {verified_sender}")
            return message_bytes.decode(), verified_sender

        except Exception as e:
            print(f"[ERROR] Decryption or verification failed: {str(e)}")
            return None, None

if __name__ == "__main__":
    engine = PGPStyleMailEngine()
    engine.generate_keys("Alice")
    engine.generate_keys("Bob")
    engine.generate_keys("Charlie")

    msg = "Confidential Legal Case Document: Meeting at 10 AM."
    pkg = engine.send_mail("Alice", ["Bob", "Charlie"], msg)
    engine.receive_mail("Bob", pkg)
