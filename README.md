# Rekor Monitor

An auditing system for Sigstore signatures

## Installation

1) Clone the repository:

        git clone https://github.com/nate-lavoy/supply-chain-security.git
   
        cd supply-chain-security

3) Set up a virtual environment (optional but recommended):

        python3 -m venv env
   
        source env/bin/activate
   
5) Install dependencies (listed below)

## Using the code

1) Create an Artifact: Start by generating the artifact that will be signed and added to Rekor.

2) Sign the Artifact: Use the Cosign tool to sign the artifact with your email ID, and save the signature and the certificate used for signing. This can be done using Cosign's bundle command.

3) Fetch the Latest Checkpoint

 - To retrieve the latest checkpoint from the Rekor server:

       python main.py -c

4) Verifying Log Inclusion

To confirm that a specific log entry exists in the transparency log and verify the artifact's signature stored in Rekor:

       python main.py --inclusion <logIndex> --artifact <artifactFilePath>`

5) Verifying Checkpoint Consistency

To ensure an older checkpoint is consistent with the current Rekor checkpoint:

       python main.py --consistency --tree-id <treeID> --tree-size <treeSize> --root-hash <rootHash>`

Provide the tree ID, tree size, and root hash from the older checkpoint for verification.

## Dependencies

 - argparse: Standard library used for argument parsing.

 - base64: Standard library for encoding and decoding base64 strings.

 - binascii: Standard library for binary and ASCII conversions.

 - hashlib: Standard library for hashing algorithms.

 - json: Standard library for JSON data handling.

 - requests: External library for making HTTP requests (install via pip install requests).

 - cryptography: External library for cryptographic functions and signature verification (install via pip install cryptography).
