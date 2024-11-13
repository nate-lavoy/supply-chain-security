import subprocess
import pytest
import json
import base64

def test_main_inclusion_argument(monkeypatch, tmp_path):
    # Create a temporary artifact file for testing
    artifact_file = tmp_path / "artifact.txt"
    artifact_file.write_text("sample artifact data")

    # Mock get_log_entry to return a sample log entry for testing
    def mock_get_log_entry(log_index, debug=False):
        return {
            "mock_key": {
                "body": base64.b64encode(b'{"spec": {"signature": {"content": "mock_signature", "publicKey": {"content": "mock_certificate"}}}}').decode("utf-8"),
                "verification": {
                    "inclusionProof": {
                        "logIndex": log_index,
                        "treeSize": log_index + 10,
                        "rootHash": "mock_root_hash",
                        "hashes": ["mock_hash1", "mock_hash2"]
                    }
                }
            }
        }

    # Mock verify_artifact_signature to bypass actual verification in this test
    def mock_verify_artifact_signature(signature, public_key, artifact_filename):
        assert artifact_filename == str(artifact_file)
        return True

    # Mock verify_inclusion to simulate a successful inclusion verification
    def mock_verify_inclusion(hasher, index_size, hashes, proof, debug=False):
        assert index_size == (126574567, 126574577)  # Example logIndex and treeSize
        assert hashes[0] == "mock_leaf_hash"
        assert proof == ["mock_hash1", "mock_hash2"]

    # Replace the real functions with the mocks for testing
    monkeypatch.setattr("rekor_monitor.main.get_log_entry", mock_get_log_entry)
    monkeypatch.setattr("rekor_monitor.main.verify_artifact_signature", mock_verify_artifact_signature)
    monkeypatch.setattr("rekor_monitor.main.verify_inclusion", mock_verify_inclusion)

    # Run the main script with inclusion argument
    result = subprocess.run(
        ["python", "-m" "rekor_monitor.main", "--inclusion", "126574567", "--artifact", str(artifact_file)],
        capture_output=True, text=True
    )

    # Check that the script ran without errors and printed the expected output
    assert result.returncode == 0
    assert "Inclusion is valid." in result.stdout
