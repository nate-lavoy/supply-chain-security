#Verifies that get_latest_checkpoint retrieves a checkpoint with the expected structure.

import json
from jsonschema import validate
import subprocess

# Define the expected schema for the checkpoint data
checkpoint_schema = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"}
    },
    "required": ["inactiveShards", "rootHash", "signedTreeHead", "treeID", "treeSize"]
}

def test_get_latest_checkpoint():
    # Run main.py as a subprocess with the '-c' flag to get the checkpoint
    result = subprocess.run(
        ['python', '-m', 'rekor_monitor.main', '-c'],
        capture_output=True,
        text=True
    )
    
    # Parse the output JSON
    output = result.stdout
    data = json.loads(output)

    # Validate the structure of the checkpoint data against the expected schema
    validate(instance=data, schema=checkpoint_schema)
