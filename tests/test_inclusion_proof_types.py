#Ensures all inclusion proof values are of the expected types

import json
import base64
from rekor_monitor.main import get_log_entry

def test_inclusion_proof():
    log_index = 146550281

    # Fetch the log entry
    result = get_log_entry(log_index)

    # Access the entry via the unique ID key
    entry_id = next(iter(result))
    entry = result[entry_id]

    # Extract and decode the base64-encoded body
    encoded_body = entry['body']
    decoded_body = json.loads(base64.b64decode(encoded_body).decode('utf-8'))

    # Ensure "inclusionProof" is present in the verification structure
    inclusion_proof = entry["verification"].get("inclusionProof", {})
    assert inclusion_proof, "Inclusion proof is missing in verification"

    # Verify that inclusionProof contains the expected keys
    expected_keys = ["checkpoint", "hashes", "logIndex", "rootHash", "treeSize"]
    for key in expected_keys:
        assert key in inclusion_proof, f"Key '{key}' missing in inclusion proof"

    # Verify each inclusion proof field has a valid type or value
    assert isinstance(inclusion_proof["logIndex"], int), "logIndex should be an integer"
    assert isinstance(inclusion_proof["treeSize"], int), "treeSize should be an integer"
    assert isinstance(inclusion_proof["checkpoint"], str), "checkpoint should be a string"
    assert isinstance(inclusion_proof["hashes"], list), "hashes should be a list"
    assert isinstance(inclusion_proof["rootHash"], str), "rootHash should be a string"
