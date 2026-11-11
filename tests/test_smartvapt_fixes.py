"""Regression checks for Ubuntu OpenSSH banner parsing/importability."""

import smartvapt_fixes


def test_smartvapt_fixes_imports_and_has_single_module_docstring():
    """Importing the helper module must remain syntactically valid."""
    assert callable(smartvapt_fixes.parse_openssh_banner)
    assert callable(smartvapt_fixes.apply_validations)


def test_parse_contiguous_ubuntu_package_revision():
    parsed = smartvapt_fixes.parse_openssh_banner(
        "OpenSSH 8.9p1 Ubuntu 3ubuntu0.17"
    )

    assert parsed is not None
    assert parsed["upstream"] == "8.9p1"
    assert parsed["release"] == "22.04"
    assert parsed["series"] == "jammy"
    assert parsed["package_version"] == "1:8.9p1-3ubuntu0.17"
    assert parsed["revision"] == "0.17"


def test_parse_hmu_release_suffix():
    parsed = smartvapt_fixes.parse_openssh_banner(
        "OpenSSH 8.9p1 Ubuntu 3ubuntu0.17~22.04.1"
    )

    assert parsed is not None
    assert parsed["release"] == "22.04"
    assert parsed["series"] == "jammy"
