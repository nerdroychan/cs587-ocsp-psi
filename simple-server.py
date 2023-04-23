from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import random
import asyncio

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


async def handle_ocsp(reader, writer):
    data = await reader.read()

    serial = int(data)

    print("Server received ocsp request for serial {}".format(serial))

    if serial in crl:
        writer.write(b"0")
    else:
        writer.write(b"1")

    writer.write_eof()
    await writer.drain()

    print("- Server replied ocsp request for serial {}".format(serial))

    writer.close()
    await writer.wait_closed()


async def main():
    server = await asyncio.start_server(
        handle_ocsp, "127.0.0.1", 23333)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f'OCSP Server running on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
