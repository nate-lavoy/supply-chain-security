#checks that verify_artifact_signature raises a ValueError when an invalid public key format is provided

import pytest
from cryptography.exceptions import InvalidSignature

from rekor_monitor.util import verify_artifact_signature

def test_verify_artifact_signature_with_invalid_public_key_format(tmp_path):
    # Create a temporary artifact file
    artifact_path = tmp_path / "artifact.txt"
    artifact_path.write_text("This is a test artifact.")

    # Dummy signature and invalid public key (not in PEM format)
    signature = b"dummy_signature"
    invalid_public_key = b"invalid_key_format"

    # Test that ValueError is raised due to malformed public key
    with pytest.raises(ValueError, match="Unable to load PEM file"):
        verify_artifact_signature(signature, invalid_public_key, str(artifact_path))
