from cryptography import x509
import asyncio

nr_certs = 1000

with open("ca.crt", "rb") as f:
    cacert = x509.load_pem_x509_certificate(f.read())

certs = {}

# load all certs
for i in range(nr_certs):
    with open("certs/cert{}.pem".format(i), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        certs[cert.serial_number] = cert


async def ocsp_client(serial):
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 23333)
    print("Server connection established")

    writer.write(str(serial).encode())
    writer.write_eof()
    await writer.drain()

    print("  - Send OCSP request for cert serial {}".format(serial))

    data = await reader.read()

    # just check the status for simplicity
    if data == b"1":
        print("  - Received status OK")
    else:
        print("  - Received status REVOKED")

    writer.close()
    await writer.wait_closed()

    print("Server connection closed")

for i in certs:
    asyncio.run(ocsp_client(certs[i].serial_number))
