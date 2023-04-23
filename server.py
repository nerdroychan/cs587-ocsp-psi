from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import random

nr_certs = 1000
nr_revokes = 50

# load CA identities

with open("ca.key", "rb") as f:
    caprivkey = serialization.load_pem_private_key(f.read(), password=b'CS587')

with open("ca.crt", "rb") as f:
    cacert = x509.load_pem_x509_certificate(f.read())

certs = []
# load all certs
for i in range(nr_certs):
    with open("certs/cert{}.pem".format(i), "rb") as f:
        certs.append(x509.load_pem_x509_certificate(f.read()))

crl = []
revokes = random.sample(range(nr_certs), nr_revokes)
for i in revokes:
    revoked = x509.RevokedCertificateBuilder().revocation_date(
            datetime.datetime.today()).serial_number(
                    certs[i].serial_number).build()
    crl.append(revoked)
    print("- CA revoked cert #{}, serial {}".format(i, certs[i].serial_number))
