"""Overwrite + verification, purge simulation, safety gates."""
import os
import random

import pytest

from evidentia.core.devices import DeviceInfo, SafetyError, assert_device_allowed
from evidentia.sanitize.engine import BLOCK, Request, SanitizeEngine, Target
from evidentia.sanitize.confirmation import ConfirmationRequired
from evidentia.sanitize.patterns import ConstPattern, RandomPattern
from evidentia.sanitize.testing import authorize_for_tests


@pytest.fixture
def img(tmp_path):
    p = tmp_path / "victim.img"
    p.write_bytes(random.Random(1).randbytes(5 * BLOCK + 12345))
    return p


def run(path, method, **kw):
    kw.setdefault("dry_run", False)
    req = Request(Target(kw.pop("kind", "image"), str(path), kw.pop("offset", 0), kw.pop("length", None)), method, **kw)
    return SanitizeEngine().run(req, authorization=None if req.dry_run else authorize_for_tests(req))


@pytest.mark.parametrize("method", ["clear-zero", "clear-random", "clear-multipass"])
@pytest.mark.parametrize("mode", ["sample", "full"])
def test_overwrite_and_verify(img, method, mode):
    r = run(img, method, verify_mode=mode)
    assert r.success and r.verification["passed"] and r.verification["mismatched_blocks"] == 0
    assert r.pre_sha256 != r.post_sha256
    if method == "clear-zero":
        assert img.read_bytes() == bytes(img.stat().st_size)


def test_random_pattern_is_seekable():
    p = RandomPattern()
    whole = p.block(0, 3 * 4096)
    assert p.block(4096, 4096) == whole[4096:8192]
    assert p.block(100, 50) == whole[100:150]


def test_verification_detects_a_bad_block(img):
    run(img, "clear-zero", verify_mode="full")
    with open(img, "r+b") as fh:  # simulate a sector the drive silently failed to write
        fh.seek(3 * BLOCK + 77)
        fh.write(b"\x01")
    fd = os.open(img, os.O_RDONLY)
    try:
        v = SanitizeEngine()._verify(fd, 0, img.stat().st_size, ConstPattern(0),
                                     Request(Target("image", str(img)), "clear-zero", verify_mode="full"),
                                     __import__("evidentia.core.jobs", fromlist=["x"]).NULL_CONTEXT)
    finally:
        os.close(fd)
    assert not v["passed"] and v["first_mismatches"] == [3 * BLOCK]


@pytest.mark.parametrize("method", ["purge-crypto-erase", "purge-nvme-sanitize-crypto", "purge-ata-secure-erase",
                                    "purge-nvme-sanitize-block"])
def test_simulated_purge(img, method):
    r = run(img, method, verify_mode="full")
    assert r.success and r.simulated and r.nist_category == "Purge"
    assert r.commands  # documented firmware commands are recorded


def test_partition_target_touches_only_its_region(img):
    before = img.read_bytes()
    run(img, "clear-zero", kind="partition", offset=BLOCK, length=2 * BLOCK)
    after = img.read_bytes()
    assert after[:BLOCK] == before[:BLOCK] and after[3 * BLOCK:] == before[3 * BLOCK:]
    assert after[BLOCK:3 * BLOCK] == bytes(2 * BLOCK)


def test_dry_run_writes_nothing(img):
    before = img.read_bytes()
    r = SanitizeEngine().run(Request(Target("image", str(img)), "clear-zero", dry_run=True))
    assert r.dry_run and r.plan and img.read_bytes() == before


def test_erase_without_confirmation_token_is_refused(img):
    before = img.read_bytes()
    with pytest.raises(ConfirmationRequired):
        SanitizeEngine().run(Request(Target("image", str(img)), "clear-zero", dry_run=False))
    assert img.read_bytes() == before


def test_original_evidence_is_protected(img):
    with pytest.raises(SafetyError):
        run(img, "clear-zero", protected_paths=[str(img)])


def test_ssd_overwrite_warning_downgrades_to_clear(img):
    r = run(img, "clear-zero", media_profile="SSD")
    assert r.nist_category == "Clear" and any("flash" in w for w in r.warnings)


def test_files_and_folders(tmp_path):
    d = tmp_path / "secrets"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_bytes(b"top secret" * 1000)
    (d / "sub" / "b.bin").write_bytes(os.urandom(5000))
    eng = SanitizeEngine()
    with pytest.raises(ConfirmationRequired):
        eng.run(Request(Target("files", str(d), paths=[str(d)]), "clear-zero", dry_run=False))
    assert (d / "a.txt").exists()
    req = Request(Target("files", str(d), paths=[str(d)]), "clear-multipass", dry_run=False)
    r = eng.run(req, authorization=authorize_for_tests(req))
    assert r.success and len(r.files) == 2 and all(f["verified"] for f in r.files)
    assert not d.exists()


def test_protected_host_paths():
    from evidentia.core.devices import assert_safe_host_path
    for p in ("/", os.path.expanduser("~"), "/usr/bin", "/System"):
        with pytest.raises(SafetyError):
            assert_safe_host_path(p)


def test_device_policy():
    sysdisk = DeviceInfo("/dev/disk0", "disk0", is_system=True, mountpoints=["/"])
    mounted = DeviceInfo("/dev/disk4", "disk4", mountpoints=["/Volumes/USB"])
    free = DeviceInfo("/dev/disk5", "disk5", media_type="USB")
    devs = [sysdisk, mounted, free]
    with pytest.raises(SafetyError, match="disabled"):
        assert_device_allowed("/dev/disk5", advanced=False, devices=devs)
    with pytest.raises(SafetyError, match="system/boot"):
        assert_device_allowed("/dev/rdisk0", advanced=True, devices=devs)
    with pytest.raises(SafetyError, match="mounted"):
        assert_device_allowed("/dev/disk4s1", advanced=True, devices=devs)
    with pytest.raises(SafetyError, match="not a recognised"):
        assert_device_allowed("/dev/disk9", advanced=True, devices=devs)
    assert assert_device_allowed("/dev/disk5", advanced=True, devices=devs) is free


def test_real_system_disk_refused():
    from evidentia.core.devices import list_devices
    system = [d for d in list_devices() if d.is_system]
    for d in system:
        with pytest.raises(SafetyError):
            assert_device_allowed(d.path, advanced=True)
