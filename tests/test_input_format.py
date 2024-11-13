#Ensure ValueError is raised when testing a negative log index

import pytest
from rekor_monitor.main import get_log_entry

def test_get_log_entry_negative_index():
    with pytest.raises(ValueError, match="Log index can't be negative"):
        get_log_entry(-1)
