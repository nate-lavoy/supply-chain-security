#Ensures a ValueError when a previous checkpoint is not present

import pytest
from rekor_monitor.main import consistency

def test_consistency_no_checkpoint_provided():
    with pytest.raises(ValueError, match="Previous checkpoint cannot be empty."):
        consistency({})
