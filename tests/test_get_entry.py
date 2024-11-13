#Ensures get_log_entry fetches a log entry and includes required keys

import json
from rekor_monitor.main import get_log_entry

def test_get_log_entry():
    log_index = 146550281  # index from my artifact, can be changed

    # Fetch the log entry
    result = get_log_entry(log_index)

    # Extract the nested dictionary, assuming result has only one top-level key
    entry_id = next(iter(result))  # Get the single key (entry ID)
    entry = result[entry_id]       # Access the actual log entry data

    # Expected keys in the log entry response
    expected_keys = ["logIndex", "body", "verification"]

    # Verify that the response contains the required keys
    assert all(key in entry for key in expected_keys), "Log entry missing required keys"

    # Check for the presence of inclusionProof and verify its structure
    if "inclusionProof" in entry["verification"]:
        inclusion_proof = entry["verification"]["inclusionProof"]

        # Define the required keys for inclusionProof
        required_keys = ["logIndex", "rootHash", "treeSize", "hashes"]

        # Verify required keys are present in inclusionProof
        assert all(key in inclusion_proof for key in required_keys), "Inclusion proof is missing required keys"
    else:
        raise AssertionError("Inclusion proof is missing from verification")
