from cryptography import x509
from cryptography.hazmat.primitives import serialization
import datetime
import random
import asyncio
import pickle

nr_certs = 1000
nr_revokes = 50

# load CA identities

with open("ca.key", "rb") as f:
    caprivkey = serialization.load_pem_private_key(f.read(), password=b"CS587")

with open("ca.crt", "rb") as f:
    cacert = x509.load_pem_x509_certificate(f.read())

certs = {}

# load all certs
for i in range(nr_certs):
    with open("certs/cert{}.pem".format(i), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        certs[cert.serial_number] = cert

crl = {}
revokes = random.sample([key for key in certs], nr_revokes)
for i in revokes:
    revoked = x509.RevokedCertificateBuilder().revocation_date(
            datetime.datetime.today()).serial_number(
                    certs[i].serial_number).build()
    crl[certs[i].serial_number] = revoked
    print("- CA revoked cert serial {}".format(certs[i].serial_number))


async def handle_server(reader, writer):
    data = await reader.read()
    msg = pickle.loads(data)
    session_id = msg[0]
    k = msg[1]

    print("CA Server received psi client session {}".format(session_id))

    writer.write(b"1")
    writer.write_eof()
    await writer.drain()
    writer.close()
    await writer.wait_closed()

    print("CA Server client connection closed")

    reader2, writer2 = await asyncio.open_connection(
        '127.0.0.1', 23334)
    print("Third-party connection established")

    new_crl = [x ^ k for x in crl]

    msg = pickle.dumps([session_id, False, new_crl])

    writer2.write(msg)
    writer2.write_eof()
    await writer2.drain()

    print("  - Send permuted crl")

    await reader2.read(1)

    writer2.close()
    await writer2.wait_closed()
    print("Third-party Server connection closed")


async def main():
    server = await asyncio.start_server(handle_server, "127.0.0.1", 23333)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f'CA Server running on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
