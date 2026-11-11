
import ssl
import urllib.request

context = ssl.create_default_context(cafile="certs/ca.crt")
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("certs/client.crt", "certs/client.key")

url = "https://localhost:8443/status"

try:
    response = urllib.request.urlopen(url, context=context)

    print("Connection successful")
    print("Response:", response.read().decode())

    sock = response.fp.raw._sock
    print("TLS Version:", sock.version())
    print("Cipher:", sock.cipher())

except Exception as e:
    print("Connection failed:", e)
