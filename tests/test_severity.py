
import pytest

from severity import assign_severity


@pytest.mark.parametrize(
    "attempts, expected",
    [
        (0, "LOW"),
        (1, "LOW"),
        (5, "LOW"),
        (6, "MEDIUM"),
        (7, "HIGH"),
        (10, "HIGH"),
        (100, "HIGH"),
    ],
)
def test_assign_severity(attempts, expected):
    assert assign_severity(attempts) == expected
