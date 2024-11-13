#Checks that extract_public_key can derive a public key from a decoded certificate.

import base64
import json
from rekor_monitor.main import get_log_entry
from rekor_monitor.util import extract_public_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

def test_extract_public_key():
    # Use a known valid log index with a certificate
    log_index = 146550281  # index from my artifact, can be changed

    # Fetch the log entry
    result = get_log_entry(log_index)

    # Access the entry via the unique ID key
    entry_id = next(iter(result))
    entry = result[entry_id]

    # Extract and decode the base64-encoded body
    encoded_body = entry['body']
    decoded_body = json.loads(base64.b64decode(encoded_body).decode('utf-8'))

    # Extract the certificate from the decoded body
    encoded_certificate = decoded_body['spec']['signature']['publicKey']['content']

    # Decode the base64-encoded certificate
    certificate = base64.b64decode(encoded_certificate)

    # Extract the public key from the certificate (assuming extract_public_key returns PEM data)
    public_key_pem = extract_public_key(certificate)

    # Load the PEM-encoded public key to get a cryptographic object
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())

    # Verify that the public key is not None and has the expected type
    assert public_key is not None, "Public key extraction failed"
    assert hasattr(public_key, "public_bytes"), "Extracted public key does not have the expected methods"
