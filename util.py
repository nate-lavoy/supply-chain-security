"""
Utility functions for cryptographic operations, including
extracting public keys from certificates and verifying artifact signatures.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

def extract_public_key(cert):
    """
    Extracts and returns the public key from a given certificate in PEM format.

    Args:
        cert (bytes): The certificate data in PEM format.

    Returns:
        bytes: The public key in PEM format.
    """
# load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

# extract the public key
    public_key = certificate.public_key()

# save the public key to a PEM file
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key

def verify_artifact_signature(signature, public_key, artifact_filename):
    """
    Verifies the signature of an artifact using the provided public key.

    Args:
        signature (bytes): The signature to verify.
        public_key (bytes): The public key in PEM format.
        artifact_filename (str): The filename of the artifact to verify.

    Raises:
        InvalidSignature: If the signature is invalid.
        UnsupportedAlgorithm: If the signature algorithm is not supported.
        ValueError: If there is an issue with the public key or signature format.
    """

    public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid.")
        return True
    except InvalidSignature as e:
        print("Signature is invalid", e)
        return False
    except ValueError as e:
        print("Exception in verifying artifact signature:", e)
        return False

    
