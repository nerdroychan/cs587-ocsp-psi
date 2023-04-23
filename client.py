from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
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


async def ocsp_client(ocspreq):
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 23333)
    print("Server connection established")

    writer.write(ocspreq.public_bytes(encoding=serialization.Encoding.DER))
    writer.write_eof()
    await writer.drain()

    print("  - Send OCSP request for cert serial {}".format(
        ocspreq.serial_number))

    data = await reader.read()

    response = ocsp.load_der_ocsp_response(data)

    # just check the status for simplicity
    if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
        print("  - Received status OK")
    else:
        print("  - Received status REVOKED")

    writer.close()
    await writer.wait_closed()

    print("Server connection closed")

for i in certs:
    ocspreq = ocsp.OCSPRequestBuilder().add_certificate(
            certs[i], cacert, hashes.SHA256()).build()
    asyncio.run(ocsp_client(ocspreq))
