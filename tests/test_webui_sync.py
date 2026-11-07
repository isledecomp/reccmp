"""Tests to assert that EntityType (and future enums) are an exact match in Python and the Javascript library for HTML report (webui)."""

import re
import pytest
from reccmp.compare.report import ReccmpStatusReport
from reccmp.types import EntityType
from reccmp.utils import write_html_report


@pytest.fixture(name="html_report", scope="module")
def fixture_html_report(tmp_path_factory: pytest.TempPathFactory) -> str:
    html = tmp_path_factory.mktemp("webui") / "report.html"
    write_html_report(str(html), ReccmpStatusReport(filename="test.exe"))
    return html.read_text(encoding="utf-8")


def test_entity_type_enum(html_report: str):
    match = re.search(r"const EntityType\b[^{]*\{([^}]*)\}", html_report)
    assert match is not None

    members = re.findall(r"(\w+)\s*:\s*(\d+)", match.group(1))
    assert {name: int(value) for name, value in members} == {
        e.name: e.value for e in EntityType
    }
