import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidentia.testdata.generator import generate  # noqa: E402


@pytest.fixture(scope="session")
def images(tmp_path_factory):
    """Generate the test images once per session; returns (dir, manifest)."""
    d = tmp_path_factory.mktemp("images")
    meta = generate(d, with_ntfs=False)
    return d, meta


@pytest.fixture(scope="session")
def truth(images):
    return {f["sha256"]: f for f in images[1]["files"]}


@pytest.fixture
def svc(tmp_path, monkeypatch):
    from evidentia.forensic.service import Evidentia
    monkeypatch.setenv("EVIDENTIA_HOME", str(tmp_path / "home"))
    s = Evidentia(tmp_path / "home")
    s.settings.examiner_name = "Test Examiner"
    yield s
    s.close()


def manifest_files(meta, image=None, states=None):
    return [f for f in meta["files"] if (image is None or f["image"] == image) and (states is None or f["state"] in states)]
