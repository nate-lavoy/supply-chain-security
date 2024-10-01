import argparse
import requests
import json
import base64
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if log_index < 0:
        raise ValueError("Log index can't be negative.")
    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    if debug:
        print(data)
    
    return data

def get_verification_proof(log_index, debug=False):
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
    signature = base64.b64decode(signature_b64)
    certificate = base64.b64decode(certificate_b64)

    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)
    proof = get_verification_proof(log_index)

    leaf_hash = compute_leaf_hash(encoded_body)
    verify_inclusion(DefaultHasher, proof["logIndex"], proof["treeSize"], leaf_hash, proof["hashes"], proof["rootHash"])


def get_latest_checkpoint(debug=False):
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url)
    response.raise_for_status()
    checkpoint = response.json()
    if debug:
        print(checkpoint)
    return checkpoint

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        raise ValueError("Previous checkpoint cannot be empty.")
    
    # Get the latest checkpoint
    latest_checkpoint = get_latest_checkpoint(debug)
    first_size = prev_checkpoint.get("treeSize")
    last_size = latest_checkpoint.get("treeSize")
    tree_id = latest_checkpoint.get("treeID")
    url = f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={first_size}&lastSize={last_size}&treeID={tree_id}"
    response = requests.get(url)
    response.raise_for_status()
    proof = response.json()

    # Verify consistency between previous and latest checkpoint
    verify_consistency(DefaultHasher, prev_checkpoint.get("treeSize"), latest_checkpoint.get("treeSize"), proof.get("hashes"), prev_checkpoint.get("rootHash"), latest_checkpoint.get("rootHash"))
    

def main():
    debug = False
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
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
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

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()

#leaf hash? last 64 characters of uuid

#consistency check api