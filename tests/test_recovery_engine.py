"""File-system-aware recovery + carving + correlation, checked against ground truth."""
import pytest

from evidentia.core.source import EvidenceSource
from evidentia.recovery import fs_recovery
from evidentia.recovery.engine import RecoveryEngine

pytestmark = pytest.mark.skipif(not fs_recovery.HAVE_TSK, reason="pytsk3 not installed")


@pytest.fixture(scope="module")
def fat_run(images, tmp_path_factory):
    d, _ = images
    with EvidenceSource(d / "fat32.img") as src:
        return RecoveryEngine().run(src, tmp_path_factory.mktemp("rec"))


def test_every_recoverable_deleted_file_is_recovered_bit_exact(fat_run, images):
    _, meta = images
    got = {i.hashes["sha256"]: i for i in fat_run.items if i.superseded_by is None}
    for f in meta["files"]:
        if f["image"] == "fat32.img" and f["state"] in ("deleted", "deleted-mismatch", "deleted-fragmented", "orphaned"):
            assert f["sha256"] in got, f"{f['path']} ({f['state']}) not recovered"
            assert got[f["sha256"]].validation.status in ("intact", "unknown")


def test_names_and_metadata_survive_for_reconstructed_files(fat_run):
    thesis = [i for i in fat_run.items if i.name == "thesis.docx" and i.superseded_by is None]
    assert thesis and thesis[0].source == "reconstructed" and thesis[0].inode is not None
    assert thesis[0].score.total >= 85


def test_extension_mismatch_flagged(fat_run):
    mm = {i.name: i.classification.type for i in fat_run.items if i.classification.mismatch and i.superseded_by is None}
    assert mm == {"invoice.pdf": "jpeg", "notes.txt": "pdf"}


def test_damaged_files_score_low(fat_run):
    for name in ("IMG_0004.jpg", "scan.png"):
        it = next(i for i in fat_run.items if i.name == name)
        assert it.validation.status == "corrupt" and it.score.total < 50


def test_orphan_found_only_by_carving(fat_run, images):
    _, meta = images
    orphan = next(f for f in meta["files"] if f["state"] == "orphaned")
    it = next(i for i in fat_run.items if i.hashes["sha256"] == orphan["sha256"])
    assert it.source == "carved" and it.inode is None and it.score.total == 80


def test_thumbnails_and_outputs_written(fat_run):
    import os
    imgs = [i for i in fat_run.items if i.classification.type == "jpeg" and i.validation.status == "intact"]
    assert all(i.thumbnail_path and os.path.exists(i.thumbnail_path) for i in imgs)
    assert all(os.path.exists(i.output_path) for i in fat_run.items)


def test_ext4_deleted_files(images, tmp_path):
    d, meta = images
    if "ext4" not in meta["images"]:
        pytest.skip("e2fsprogs not available")
    with EvidenceSource(d / "ext4.img") as src:
        res = RecoveryEngine().run(src, tmp_path)
    got = {i.hashes["sha256"] for i in res.items}
    for f in meta["files"]:
        if f["image"] == "ext4.img" and f["state"].startswith("deleted"):
            assert f["sha256"] in got, f["path"]


def test_partitioned_disk(images, tmp_path):
    d, meta = images
    with EvidenceSource(d / "disk_mbr.img") as src:
        res = RecoveryEngine().run(src, tmp_path)
    assert [p["fs_type"] for p in res.partitions][:1] == ["FAT32"]
    assert res.stats["reconstructed"] >= 1
