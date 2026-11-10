from scalable_group_rekeying import hello


def test_hello() -> None:
    assert "scalable-group-rekeying" in hello()
