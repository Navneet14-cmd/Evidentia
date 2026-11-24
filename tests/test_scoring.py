from evidentia.recovery.scoring import compute_score

BASE = dict(has_name=True, has_times=True, has_inode=True, size_consistent=True, validation_status="intact",
            fragmentation="contiguous", entropy=7.8, expected_entropy=(7.0, 8.0), zero_ratio=0.0)


def s(**kw):
    return compute_score(**{**BASE, **kw})


def test_perfect_fs_recovery_scores_100():
    r = s()
    assert r.total == 100 and r.grade == "high"
    assert sum(c["points"] for c in r.components) == r.total
    assert {c["key"] for c in r.components} == {"metadata", "validation", "fragmentation", "entropy"}


def test_ordering_of_evidence_quality():
    carved = s(has_name=False, has_times=False, has_inode=False, size_consistent=False)
    rebuilt = s(fragmentation="reconstructed")
    partial = s(validation_status="partial", fragmentation="unknown")
    corrupt = s(validation_status="corrupt", fragmentation="broken")
    assert s().total > rebuilt.total > partial.total > corrupt.total
    assert carved.total == 80
    assert corrupt.grade == "low"


def test_entropy_and_zero_blocks_penalised():
    assert s(entropy=3.0).total < s().total
    assert s(zero_ratio=0.5).total < s().total
    comp = next(c for c in s(zero_ratio=0.5).components if c["key"] == "entropy")
    assert "zero-filled" in comp["reason"]


def test_bounds():
    r = s(has_name=False, has_times=False, has_inode=False, size_consistent=False, validation_status="corrupt",
          fragmentation="broken", entropy=0.0, zero_ratio=1.0)
    assert 0 <= r.total <= 100
