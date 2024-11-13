#verifies that verify_artifact_signature raises a FileNotFoundError when the specified artifact file is missing.

import pytest
from rekor_monitor.util import verify_artifact_signature

def test_verify_artifact_signature_missing_file():
    # Prepare a valid public key and dummy signature
    public_key_pem = b"""-----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjve5m8l433OMsNN3N/og6qOagZ+9
    wGEfZBSm5hFboH6dgte4TqgshZJV32eVLW9sGFWX2IIZhfw+B74BxVN5yg==
    -----END PUBLIC KEY-----"""
    
    signature = b"dummy_signature_data"

    # Test with a non-existent file
    with pytest.raises(FileNotFoundError):
        verify_artifact_signature(signature, public_key_pem, "non_existent_artifact.txt")
