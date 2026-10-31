"""Every change bumps the version (netmon/__init__.py) and adds its CHANGELOG.md section; the image tag follows."""
import os
import re

from netmon import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_format_changelog_section_and_image_tag():
    assert re.fullmatch(r"\d+\.\d{2}", __version__)
    log = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    heads = re.findall(r"^## v(\d+\.\d{2})\b", log, re.M)
    assert heads and heads[0] == __version__, "newest CHANGELOG.md section must be the current version"
    assert len(heads) == len(set(heads))
    compose = os.path.join(ROOT, "docker-compose.yml")
    if os.path.exists(compose):   # not inside the image
        assert f"image: netmon-app:{__version__}" in open(compose, encoding="utf-8").read()

