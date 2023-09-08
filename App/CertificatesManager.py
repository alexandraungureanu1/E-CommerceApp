from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import datetime
import configparser


class CertificateManager:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

    def create_certificate(self, location):
        # Generate a new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.get("CA", "country_name")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config.get("CA", "state_or_province_name")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config.get("CA", "locality_name")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.get("CA", "organization_name")),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config.get("CA", "common_name")),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.config.get("CA", "common_name"))]),
            critical=False
        ).sign(
            private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Save the private key, public key and certificate to files
        with open(location + "/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(location + "/public_key.pem", "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        with open(location + "/certificate.pem", "wb") as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    def validate_certificate(self, certificate_location):
        # Load the certificate from file
        with open(certificate_location, "rb") as f:
            cert_bytes = f.read()

        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Check that the certificate is currently valid
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            print("Certificate is not valid")
            exit(1)

        # Check that the certificate has a valid signature
        public_key = cert.public_key()
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            print("Invalid signature on certificate")
            return False

        # Check that the certificate has the expected hostname
        expected_hostname = "localhost"
        if not any(
                x.value == expected_hostname
                for x in cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
        ):
            print("Certificate does not have the expected hostname")
            return False

        # Check that the certificate has the expected issuer
        expected_issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.get("CA", "country_name")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config.get("CA", "state_or_province_name")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config.get("CA", "locality_name")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.get("CA", "organization_name")),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config.get("CA", "common_name")),
        ])
        if cert.issuer != expected_issuer:
            print("Certificate is not issued by the expected authority")
            return False

        return True


# certificateManager = CertificateManager()
# certificateManager.create_certificate("merchant_info")
# certificateManager.create_certificate("bank_info")
