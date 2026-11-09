"""Keep the operator guide's links, profiles, and CLI examples usable offline."""

import re
import shlex
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from hardener import cli
from hardener.validation import load_catalog, parse_yaml, validate

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()


def fenced_blocks(language):
    return re.findall(rf"^```{language}\n(.*?)^```", README, re.MULTILINE | re.DOTALL)


def test_published_documentation_omits_personal_repository_owner():
    guides = [ROOT / "README.md", ROOT / "web/README.md", *(ROOT / "docs").rglob("*.md")]
    for guide in guides:
        assert "don-milsey-miller" not in guide.read_text(encoding="utf-8").casefold(), guide


def test_readme_relative_links_and_heading_targets_exist():
    links = re.findall(r"!?\[[^\]\n]*\]\(([^)\s]+)\)", README)
    assert links, "README must link to its supporting documentation"
    for link in links:
        url = urlsplit(link)
        if url.scheme or url.netloc:
            continue
        path = ROOT / unquote(url.path) if url.path else ROOT / "README.md"
        assert path.exists(), f"Broken README link: {link}"
        if url.fragment:
            headings = re.findall(r"^#{1,6} (.+)$", path.read_text(), re.MULTILINE)
            anchors = {
                re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-") for heading in headings
            }
            assert unquote(url.fragment) in anchors, f"Missing heading: {link}"


def test_readme_yaml_examples_validate_against_shipped_catalog():
    examples = fenced_blocks("yaml")
    assert examples, "README must show a complete profile"
    catalog = load_catalog()
    for example in examples:
        profile = parse_yaml(example.encode())
        assert validate(profile, catalog)


def documented_cli_commands():
    commands = []
    for block in fenced_blocks("bash"):
        for line in block.replace("\\\n", "").splitlines():
            if line.startswith("hardener "):
                commands.append(line)
    return commands


@pytest.mark.parametrize("command", documented_cli_commands())
def test_readme_cli_examples_parse_without_contacting_a_target(command, monkeypatch):
    monkeypatch.chdir(ROOT)
    # The guide reassigns PROFILE after downloading an export. Exercise the parser
    # with a shipped valid profile, without requiring a user's Downloads folder.
    command = command.replace("$PROFILE", "profiles/examples/server-five-controls.yaml")
    command = command.replace("$RUN", "reports/readme-test")

    def check_remote_arguments(args, profile, digest, catalog):
        validate(profile, catalog, mode=args.mode)
        assert args.inventory == "inventory.local.ini"
        assert args.target == "test-vm"
        assert args.output
        return 0

    monkeypatch.setattr(cli, "execute", check_remote_arguments)
    monkeypatch.setattr(cli, "inventory_target", lambda *args: ROOT / "inventory.example.ini")
    monkeypatch.setattr(cli.recovery, "rehearse", lambda *args: 0)
    arguments = shlex.split(command)[1:]
    if arguments == ["--help"]:
        with pytest.raises(SystemExit) as result:
            cli.main(arguments)
        assert result.value.code == 0
    else:
        assert cli.main(arguments) == 0
