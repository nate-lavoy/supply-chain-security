#Confirms that signature and certificate fields in the log entry are correctly base64-decoded.

import base64
import json
from rekor_monitor.main import get_log_entry

def test_decode_signature_and_certificate():
    # Use a known valid log index with a signature and certificate
    log_index = 146550281  # index from my artifact, can be changed

    # Fetch the log entry
    result = get_log_entry(log_index)

    # Access the entry via the unique ID key
    entry_id = next(iter(result))
    entry = result[entry_id]

    # Extract and decode the base64-encoded body
    encoded_body = entry['body']
    decoded_body = json.loads(base64.b64decode(encoded_body).decode('utf-8'))

    # Extract the signature and certificate from the decoded body
    encoded_signature = decoded_body['spec']['signature']['content']
    encoded_certificate = decoded_body['spec']['signature']['publicKey']['content']

    # Decode the base64-encoded signature and certificate
    signature = base64.b64decode(encoded_signature)
    certificate = base64.b64decode(encoded_certificate)

    # Check that the decoded data is not empty, indicating successful decoding
    assert signature, "Decoded signature is empty"
    assert certificate, "Decoded certificate is empty"
