from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import uuid
import random

# Create a CA
one_day = datetime.timedelta(1, 0, 0)
caprivkey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)
capubkey = caprivkey.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Chen'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'CS587')])) \
    .not_valid_before(datetime.datetime.today() - one_day) \
    .not_valid_after(datetime.datetime(2025, 1, 1)) \
    .serial_number(int(uuid.uuid4())) \
    .public_key(capubkey) \
    .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True) \
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'UIC')]))

cacert = builder.sign(
    private_key=caprivkey, algorithm=hashes.SHA256(),
    backend=default_backend()
)

with open("ca.key", "wb") as f:
    f.write(caprivkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b'CS587')
    ))

with open("ca.crt", "wb") as f:
    f.write(cacert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))

print("CA generated")


def sign_certificate_request(csr_cert, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.today() - one_day
    ).not_valid_after(
        datetime.datetime(2025, 1, 1)
    ).sign(private_ca_key, hashes.SHA256())
    return cert


nr_certs = 10
nr_revokes = 2
# Randomly create 100 certs, and revoke 10 of them

certs = []

for i in range(nr_certs):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open("certs/key{}.pem".format(i), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b'CS587'),
        ))
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Illinois"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chicago"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UIC"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"{}.uic.edu".format(i)),
        ]),
        critical=False,
        ).sign(key, hashes.SHA256())
    with open("certs/csr{}.pem".format(i), "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # sign!
    signed = sign_certificate_request(csr, cacert, caprivkey)
    with open("certs/cert{}.pem".format(i), "wb") as f:
        f.write(signed.public_bytes(serialization.Encoding.PEM))

    certs.append(signed)
    print("- CA signed cert #{}, serial {}".format(i, signed.serial_number))

rcerts = []

for i in range(nr_revokes):
    rand = random.randrange(0, nr_certs)
    serial = certs[rand].serial_number
    print("* CA revoked cert with serial {}".format(serial))
    rcerts.append(x509.RevokedCertificateBuilder().revocation_date(
            datetime.datetime.today()).serial_number(serial).build())
