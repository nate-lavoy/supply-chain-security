"""
Main module for Rekor Verifier.

Functionalities to verify inclusion and consistency of entries in the Rekor Transparency Log.
"""
import argparse
import json
import base64

import requests

from rekor_monitor.util import extract_public_key, verify_artifact_signature
from rekor_monitor.merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    """
    Retrieves a log entry from the Rekor Transparency Log based on the provided log index.

    Args:
        log_index (int): The index of the log entry to retrieve.

    Returns:
        dict: The retrieved log entry data.

    Raises:
        ValueError: If the log index is negative.
        requests.HTTPError: If the HTTP request to the Rekor server fails.
    """
    # verify that log index value is sane
    if log_index < 0:
        raise ValueError("Log index can't be negative.")
    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()
    if debug:
        print(data)
    return data

def get_verification_proof(log_index, debug=False):
    """
    Retrieves the inclusion proof for a specific log entry.

    Args:
        log_index (int): The index of the log entry.

    Returns:
        dict: The inclusion proof data.
    """
    # verify that log index value is sane
    if log_index < 0:
        raise ValueError("Log index can't be negative.")
    data = get_log_entry(log_index, debug)
    main_key = list(data.keys())[0]
    entry = data[main_key]
    verification = entry.get("verification", {})
    proof = verification.get("inclusionProof")
    return proof

def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verifies the inclusion of an artifact in the Rekor Transparency Log.

    Args:
        log_index (int): The index of the log entry.
        artifact_filepath (str): The file path of the artifact to verify.

    Raises:
        ValueError: If log index or artifact filepath is invalid.
    """
    # verify that log index and artifact filepath values are sane
    if log_index < 0:
        raise ValueError("Log index can't be negative.")
    if not artifact_filepath:
        raise ValueError("Need an artifact path")
    data = get_log_entry(log_index, debug)
    main_key = list(data.keys())[0]
    entry = data[main_key]
    encoded_body = entry.get("body")
    decoded_body = base64.b64decode(encoded_body).decode('utf-8')
    decoded = json.loads(decoded_body)
    signature_b64 = decoded['spec']['signature']['content']
    certificate_b64 = decoded['spec']['signature']['publicKey']['content']
    # Decode signature and certificate from Base64 to bytes
    public_key = extract_public_key(base64.b64decode(certificate_b64))
    verify_artifact_signature(base64.b64decode(signature_b64), public_key, artifact_filepath)
    proof = get_verification_proof(log_index)
    leaf_hash = compute_leaf_hash(encoded_body)
    verify_inclusion(DefaultHasher, (proof["logIndex"], proof["treeSize"]),
                     (leaf_hash, proof["rootHash"]), proof["hashes"])

def get_latest_checkpoint(debug=False):
    """
    Retrieves the latest checkpoint from the Rekor server.

    Returns:
        dict: The latest checkpoint data.

    Raises:
        requests.HTTPError: If the HTTP request to the Rekor server fails.
    """
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    checkpoint = response.json()
    if debug:
        print(checkpoint)
    return checkpoint

def consistency(prev_checkpoint, debug=False):
    """
    Verifies the consistency between a previous checkpoint and the latest checkpoint.

    Args:
        prev_checkpoint (dict): The previous checkpoint data.

    Raises:
        ValueError: If the previous checkpoint is empty.
        requests.HTTPError: If the HTTP request to the Rekor server fails.
    """
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        raise ValueError("Previous checkpoint cannot be empty.")
    # Get the latest checkpoint
    latest_checkpoint = get_latest_checkpoint(debug)
    first_size = prev_checkpoint.get("treeSize")
    last_size = latest_checkpoint.get("treeSize")
    tree_id = latest_checkpoint.get("treeID")
    url = f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={first_size}&lastSize={last_size}&treeID={tree_id}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    proof = response.json()
    # Verify consistency between previous and latest checkpoint
    verify_consistency(DefaultHasher, (prev_checkpoint.get("treeSize"),
                       latest_checkpoint.get("treeSize")),
                       proof.get("hashes"), (prev_checkpoint.get("rootHash"),
                       latest_checkpoint.get("rootHash")))

def main():
    """
    The main entry point for the Rekor Verifier.

    Executes the appropriate verification actions based on the provided options.
    """
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(args.debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, args.debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, args.debug)

if __name__ == "__main__":
    main()
