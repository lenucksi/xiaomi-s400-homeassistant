"""Check that hardware verification cannot pass without decoded data."""

from __future__ import annotations

import pytest

from tools.s400_verify_local import _measurement_result


@pytest.mark.parametrize(
    ("fe95_count", "gatt_count", "expected"),
    [(0, 0, 1), (1, 0, 0), (0, 1, 0)],
)
def test_measurement_result(fe95_count: int, gatt_count: int, expected: int) -> None:
    assert _measurement_result(fe95_count, gatt_count) == expected
