
import json
import time
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# CONFIGURATION

USERNAME = "student"
PASSWORD = "Student@123"
SALT = b"SIMATS_KERBEROS_SALT"

TGS_KEY = Fernet.generate_key()
SERVICE_KEY = Fernet.generate_key()

KDC_AVAILABLE = True
REPLAY_CACHE = set()

CLOCK_SKEW = 60


# KEY GENERATION

def generate_client_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=200000
    )

    key = kdf.derive(password.encode())

    return base64.urlsafe_b64encode(key)


CLIENT_KEY = generate_client_key(PASSWORD)


# ENCRYPTION AND DECRYPTION

def encrypt_data(data, key):
    message = json.dumps(data).encode()
    return Fernet(key).encrypt(message)


def decrypt_data(token, key):
    try:
        message = Fernet(key).decrypt(token)
        return json.loads(message.decode())

    except InvalidToken:
        raise ValueError("Authentication or decryption failed")


# AUTHENTICATION SERVER EXCHANGE

def authentication_server(username, ticket_lifetime=3600):

    if not KDC_AVAILABLE:
        raise ConnectionError("KDC is unavailable")

    if username != USERNAME:
        raise ValueError("Unknown user")

    session_key = Fernet.generate_key()

    current_time = int(time.time())

    tgt_data = {
        "client": username,
        "session_key": session_key.decode(),
        "issued_at": current_time,
        "expires_at": current_time + ticket_lifetime
    }

    tgt = encrypt_data(tgt_data, TGS_KEY)

    response = {
        "session_key": session_key.decode(),
        "tgt": tgt.decode()
    }

    encrypted_response = encrypt_data(
        response,
        CLIENT_KEY
    )

    return encrypted_response


# CLIENT PROCESSES AS REPLY

def client_process_as_reply(encrypted_response):

    response = decrypt_data(
        encrypted_response,
        CLIENT_KEY
    )

    session_key = response["session_key"].encode()
    tgt = response["tgt"].encode()

    return tgt, session_key


# AUTHENTICATOR GENERATION

def create_authenticator(username, session_key, offset=0):

    authenticator = {
        "client": username,
        "timestamp": int(time.time()) + offset
    }

    return encrypt_data(authenticator, session_key)


# TICKET GRANTING SERVER EXCHANGE

def ticket_granting_server(
    tgt,
    tgt_session_key,
    service_name,
    authenticator_offset=0
):

    if not KDC_AVAILABLE:
        raise ConnectionError("KDC is unavailable")

    tgt_data = decrypt_data(tgt, TGS_KEY)

    current_time = int(time.time())

    if current_time > tgt_data["expires_at"]:
        raise ValueError("Ticket-Granting Ticket has expired")

    authenticator = create_authenticator(
        tgt_data["client"],
        tgt_session_key,
        authenticator_offset
    )

    auth_data = decrypt_data(
        authenticator,
        tgt_session_key
    )

    if auth_data["client"] != tgt_data["client"]:
        raise ValueError("Client authentication failed")

    if abs(current_time - auth_data["timestamp"]) > CLOCK_SKEW:
        raise ValueError("Clock skew exceeded")

    service_session_key = Fernet.generate_key()

    service_ticket_data = {
        "client": tgt_data["client"],
        "service": service_name,
        "session_key": service_session_key.decode(),
        "issued_at": current_time,
        "expires_at": current_time + 1800
    }

    service_ticket = encrypt_data(
        service_ticket_data,
        SERVICE_KEY
    )

    response = {
        "service_ticket": service_ticket.decode(),
        "service_session_key": service_session_key.decode()
    }

    encrypted_response = encrypt_data(
        response,
        tgt_session_key
    )

    return encrypted_response


# CLIENT PROCESSES TGS REPLY

def client_process_tgs_reply(encrypted_response, tgt_session_key):

    response = decrypt_data(
        encrypted_response,
        tgt_session_key
    )

    service_ticket = response["service_ticket"].encode()

    service_session_key = response["service_session_key"].encode()

    return service_ticket, service_session_key


# APPLICATION SERVER AUTHENTICATION

def application_server(
    service_ticket,
    authenticator,
    replay_protection=True
):

    ticket_data = decrypt_data(
        service_ticket,
        SERVICE_KEY
    )

    current_time = int(time.time())

    if current_time > ticket_data["expires_at"]:
        raise ValueError("Service ticket expired")

    session_key = ticket_data["session_key"].encode()

    auth_data = decrypt_data(
        authenticator,
        session_key
    )

    if auth_data["client"] != ticket_data["client"]:
        raise ValueError("Client identity mismatch")

    if abs(current_time - auth_data["timestamp"]) > CLOCK_SKEW:
        raise ValueError("Clock skew exceeded")

    replay_id = (
        auth_data["client"],
        auth_data["timestamp"]
    )

    if replay_protection:

        if replay_id in REPLAY_CACHE:
            raise ValueError("Replay attack detected")

        REPLAY_CACHE.add(replay_id)

    # MUTUAL AUTHENTICATION RESPONSE

    server_response = {
        "server": "Hospital Application Server",
        "timestamp": current_time,
        "status": "Authenticated"
    }

    encrypted_response = encrypt_data(
        server_response,
        session_key
    )

    return encrypted_response


# CLIENT VERIFIES SERVER RESPONSE

def verify_server_response(response, session_key):

    data = decrypt_data(response, session_key)

    return (
        data["server"] == "Hospital Application Server"
        and data["status"] == "Authenticated"
    )


# NORMAL KERBEROS AUTHENTICATION

def normal_authentication():

    print("\nEXPERIMENT 1: NORMAL KERBEROS AUTHENTICATION")
    print("=" * 65)

    print("Step 1: Client requests authentication from AS")

    as_response = authentication_server(USERNAME)

    print("AS: Authentication request accepted")

    print("Step 2: Client decrypts AS response")

    tgt, tgt_session_key = client_process_as_reply(
        as_response
    )

    print("Client: Ticket-Granting Ticket received")

    print("Step 3: Client requests service ticket from TGS")

    tgs_response = ticket_granting_server(
        tgt,
        tgt_session_key,
        "Hospital Application Server"
    )

    print("TGS: Service ticket generated")

    print("Step 4: Client decrypts TGS response")

    service_ticket, service_session_key = client_process_tgs_reply(
        tgs_response,
        tgt_session_key
    )

    print("Client: Service ticket received")

    print("Step 5: Client sends ticket and authenticator")

    authenticator = create_authenticator(
        USERNAME,
        service_session_key
    )

    server_response = application_server(
        service_ticket,
        authenticator
    )

    print("Application Server: Client authenticated")

    print("Step 6: Client verifies server response")

    print(
        "Mutual Authentication:",
        verify_server_response(
            server_response,
            service_session_key
        )
    )

    print("Final Result: ACCESS GRANTED")


# REPLAY ATTACK EXPERIMENT

def replay_attack_experiment():

    print("\nEXPERIMENT 2: AUTHENTICATOR REPLAY ATTACK")
    print("=" * 65)

    as_response = authentication_server(USERNAME)

    tgt, tgt_session_key = client_process_as_reply(
        as_response
    )

    tgs_response = ticket_granting_server(
        tgt,
        tgt_session_key,
        "Hospital Application Server"
    )

    service_ticket, service_session_key = client_process_tgs_reply(
        tgs_response,
        tgt_session_key
    )

    captured_authenticator = create_authenticator(
        USERNAME,
        service_session_key
    )

    print("Attacker captures the authenticator")

    print("\nWithout Replay Protection:")

    try:
        application_server(
            service_ticket,
            captured_authenticator,
            replay_protection=False
        )

        print("First Request: ACCEPTED")

        application_server(
            service_ticket,
            captured_authenticator,
            replay_protection=False
        )

        print("Replayed Request: ACCEPTED")

    except ValueError as error:
        print("Rejected:", error)

    print("\nWith Replay Protection:")

    REPLAY_CACHE.clear()

    try:
        application_server(
            service_ticket,
            captured_authenticator,
            replay_protection=True
        )

        print("First Request: ACCEPTED")

    except ValueError as error:
        print("First Request: REJECTED -", error)

    try:
        application_server(
            service_ticket,
            captured_authenticator,
            replay_protection=True
        )

        print("Replayed Request: ACCEPTED")

    except ValueError as error:
        print("Replayed Request: REJECTED -", error)


# EXPIRED TICKET EXPERIMENT

def expired_ticket_experiment():

    print("\nEXPERIMENT 3: EXPIRED TICKET")
    print("=" * 65)

    as_response = authentication_server(
        USERNAME,
        ticket_lifetime=-10
    )

    tgt, tgt_session_key = client_process_as_reply(
        as_response
    )

    try:
        ticket_granting_server(
            tgt,
            tgt_session_key,
            "Hospital Application Server"
        )

        print("Result: ACCEPTED")

    except ValueError as error:
        print("Result: REJECTED")
        print("Reason:", error)


# CLOCK SKEW EXPERIMENT

def clock_skew_experiment():

    print("\nEXPERIMENT 4: CLOCK SKEW FAILURE")
    print("=" * 65)

    as_response = authentication_server(USERNAME)

    tgt, tgt_session_key = client_process_as_reply(
        as_response
    )

    try:
        ticket_granting_server(
            tgt,
            tgt_session_key,
            "Hospital Application Server",
            authenticator_offset=300
        )

        print("Result: ACCEPTED")

    except ValueError as error:
        print("Result: REJECTED")
        print("Reason:", error)


# KDC UNAVAILABILITY EXPERIMENT

def kdc_failure_experiment():

    global KDC_AVAILABLE

    print("\nEXPERIMENT 5: KDC UNAVAILABILITY")
    print("=" * 65)

    KDC_AVAILABLE = False

    try:
        authentication_server(USERNAME)

        print("Result: ACCEPTED")

    except ConnectionError as error:
        print("Result: REJECTED")
        print("Reason:", error)

    finally:
        KDC_AVAILABLE = True


# MAIN PROGRAM

if __name__ == "__main__":

    print("KERBEROS AUTHENTICATION SIMULATION")
    print("=" * 65)

    normal_authentication()

    replay_attack_experiment()

    expired_ticket_experiment()

    clock_skew_experiment()

    kdc_failure_experiment()

    print("\nALL KERBEROS EXPERIMENTS COMPLETED")
