from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
import asyncio
import secrets
import uuid
import pickle

nr_certs = 1000

with open("ca.crt", "rb") as f:
    cacert = x509.load_pem_x509_certificate(f.read())

certs = {}

nr_revoked = 0

# load all certs
for i in range(nr_certs):
    with open("certs/cert{}.pem".format(i), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        certs[cert.serial_number] = cert


async def psi_client(ocspreq):
    global nr_revoked

    serial = ocspreq.serial_number
    k = secrets.randbits(512)
    session_id = uuid.uuid4().hex

    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 23333)
    print("CA Server connection established, session {}".format(
        session_id))

    msg = pickle.dumps([session_id, k])

    writer.write(msg)
    writer.write_eof()
    await writer.drain()

    print("  - Send PRP seed for serial {}".format(serial))
    await reader.read(1)
    print("  - PRP seed ACK received")

    writer.close()
    await writer.wait_closed()
    print("CA Server connection closed")

    reader2, writer2 = await asyncio.open_connection(
        '127.0.0.1', 23334)
    print("Third-party connection established")

    msg = pickle.dumps([session_id, True, k ^ serial])

    writer2.write(msg)
    writer2.write_eof()
    await writer2.drain()

    print("  - Send permuted serial for serial {}".format(serial))
    data = await reader2.read(1)
    print("  - Intersection received")
    if (data == b"1"):
        print("  - Received status REVOKED")
        nr_revoked += 1
        print(" - NR_REVOKED: ", nr_revoked)
    else:
        print("  - Received status OK")

    writer2.close()
    await writer2.wait_closed()
    print("Third-party Server connection closed")

for i in certs:
    ocspreq = ocsp.OCSPRequestBuilder().add_certificate(
            certs[i], cacert, hashes.SHA256()).build()
    asyncio.run(psi_client(ocspreq))
