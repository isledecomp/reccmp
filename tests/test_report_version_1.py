"""Tests for serializing and deserializing a version 1 report.
We added some fields during the format's lifetime, but we expect any file
to be compatible because missing fields get a default value."""

import json
from datetime import datetime
import pytest
from reccmp.compare.report import (
    ReccmpStatusReport,
    ReccmpComparedEntity,
    ReccmpReportDeserializeError,
    deserialize_reccmp_report,
    serialize_reccmp_report,
)
from reccmp.compare.diff import CombinedDiffOutput, RawDiffOutput
from reccmp.types import EntityType


def create_json(entities: list[dict] | None = None, **kwargs) -> str:
    """Helper to create a report in version 1 format serialied to JSON."""
    obj = {
        "file": "test.exe",
        "format": 1,
        "timestamp": 1234567890.0,
        "data": entities if entities is not None else [],
    }
    obj.update(kwargs)
    return json.dumps(obj)


def create_entity(**kwargs) -> dict:
    """Helper to set required fields for an entity. Add or overwrite fields using kwargs."""
    entity = {"address": "0x100", "name": "test", "matching": 1.0}
    entity.update(kwargs)
    return entity


def sample_rdiff() -> RawDiffOutput:
    return RawDiffOutput(
        codes=[("equal", 0, 1, 0, 1)],
        orig_inst=[("0x0", "xor eax, eax")],
        recomp_inst=[("0x0", "ret ")],
    )


def sample_udiff() -> CombinedDiffOutput:
    """Returns unified diff with type for mypy coercion."""
    return [
        (
            "@@ -0x0,1 +0x0,1 @@",
            [{"orig": [("0x0", "nop ")], "recomp": [("0x0", "ret ")]}],
        )
    ]


def test_deserialize_empty_report():
    """Should deserialize a report with no entities."""
    report = deserialize_reccmp_report(create_json())
    assert report.filename == "test.exe"
    assert report.from_version == 1
    assert report.function_total == 0
    assert not report.entities


def test_deserialize_one_entity():
    """Should deserialize a report with one entity."""
    report = deserialize_reccmp_report(create_json([create_entity()]))
    assert 0x100 in report.entities

    # Default values from create_entity()
    e = report.entities[0x100]
    assert e.orig_addr == 0x100
    assert e.name == "test"
    assert e.accuracy == 1.0

    # Presumed to be a function because no entity type is set.
    assert e.is_function()


def test_deserialize_if_missing_required_fields():
    """Throw if any entity is missing these required fields: address, name, matching."""
    for field in ("address", "name", "matching"):
        entity = create_entity()
        del entity[field]
        with pytest.raises(ReccmpReportDeserializeError):
            deserialize_reccmp_report(create_json([entity]))


def test_deserialize_defaults_for_optional_fields():
    """Set a default value if any of these "optional" fields are not set."""
    report = deserialize_reccmp_report(create_json([create_entity()]))
    e = report.entities[0x100]

    assert e.type is None
    assert e.recomp_addr is None
    assert e.is_stub is False
    assert e.is_library is False
    assert e.is_effective_match is False
    assert e.udiff is None
    assert e.recomp_addr_various is False

    # Cannot be set from a version 1 report.
    assert e.rdiff is None


def test_deserialize_explicit_null_fields():
    """Can use implicit or explicit null for optional fields."""
    for field in ("recomp", "stub", "library", "effective", "diff", "type"):
        entity = create_entity()
        entity[field] = None
        report = deserialize_reccmp_report(create_json([entity]))
        e = report.entities[0x100]

        assert e.type is None
        assert e.recomp_addr is None
        assert e.is_stub is False
        assert e.is_library is False
        assert e.is_effective_match is False
        assert e.udiff is None


def test_deserialize_null_type_presumed_function():
    """We began to store the entity type in serialized reports starting with #392.
    If the type is null, we assume the entity is a function."""
    entity = create_entity(recomp="0x100", matching=0.5)
    report = deserialize_reccmp_report(create_json([entity]))
    e = report.entities[0x100]

    assert e.type is None
    assert e.is_function() is True
    assert report.function_total == 1


@pytest.mark.xfail(reason="Potential improvement.")
def test_deserialize_guess_vtable_type():
    """Reasonable assumption about entity type (if it is None) using the entity's name"""
    entity = create_entity(name="Pizza::`vftable'", recomp="0x100", matching=0.5)
    report = deserialize_reccmp_report(create_json([entity]))
    e = report.entities[0x100]

    assert e.type is None
    assert e.is_function() is False
    assert report.function_total == 0


def test_deserialize_valid_type():
    """Deserialize entity type using the integer value from the EntityType enum."""
    entity = create_entity(type=int(EntityType.VTABLE))
    report = deserialize_reccmp_report(create_json([entity]))
    assert report.entities[0x100].type == EntityType.VTABLE


def test_deserialize_invalid_type():
    """If the type number for an entity is not part of the
    EntityType enum, set the entity type to None."""
    report = deserialize_reccmp_report(create_json([create_entity(type=999)]))
    assert report.entities[0x100].type is None


@pytest.mark.parametrize("address", ["", "0x", "hello", "1.5", "0x1zz", "-"])
def test_deserialize_invalid_address_string(address: str):
    """Fail the entire report if we cannot deserialize an address."""
    with pytest.raises(ReccmpReportDeserializeError):
        deserialize_reccmp_report(create_json([create_entity(address=address)]))

    with pytest.raises(ReccmpReportDeserializeError):
        deserialize_reccmp_report(create_json([create_entity(recomp=address)]))


def test_deserialize_address_must_be_a_string():
    """Version 1 addresses are hex strings, not numbers."""
    with pytest.raises(ReccmpReportDeserializeError):
        deserialize_reccmp_report(create_json([create_entity(address=0x100)]))

    with pytest.raises(ReccmpReportDeserializeError):
        deserialize_reccmp_report(create_json([create_entity(recomp=0x100)]))


def test_deserialize_recomp_addr_various():
    """For an entity with varying recomp addresses created by `reccmp-aggregate`
    handle the magic string "various" and set the correct properties."""
    entity = create_entity(recomp="various")
    report = deserialize_reccmp_report(create_json([entity]))
    e = report.entities[0x100]

    assert e.recomp_addr is None
    assert e.recomp_addr_various is True
    assert e.is_matched() is True


def test_deserialize_recomp_addr_various_exact():
    """The magic string must be "various" exactly."""
    for various_variant in ("various ", "Various", "VARIOUS"):
        entity = create_entity(recomp=various_variant)
        with pytest.raises(ReccmpReportDeserializeError):
            deserialize_reccmp_report(create_json([entity]))


def test_deserialize_null_function_total():
    """If `function_total` is null or not set, recalculate by counting
    the function entities in the report."""
    entities = [
        create_entity(address="0x100", recomp="0x100"),
        create_entity(address="0x200", recomp="0x200", type=int(EntityType.VTABLE)),
    ]
    report = deserialize_reccmp_report(create_json(entities, function_total=None))
    assert report.function_total == 1


def test_deserialize_function_total_lower_than_count():
    """Count the number of function entities when deserializing.
    Use this value or the report's serialized count, whichever is higher."""
    entities = [
        create_entity(address="0x100", recomp="0x100"),
        create_entity(address="0x200", recomp="0x200"),
    ]
    report = deserialize_reccmp_report(create_json(entities, function_total=1))
    assert report.function_total == 2


def test_deserialize_function_total_higher_than_count():
    """Do not overwrite the serialized function total if it is higher than the count."""
    entities = [create_entity(recomp="0x100")]
    report = deserialize_reccmp_report(create_json(entities, function_total=100))
    assert report.function_total == 100


def test_serialize_empty():
    filename = "test.exe"
    report = ReccmpStatusReport(filename=filename)
    obj = json.loads(serialize_reccmp_report(report))

    assert obj["file"] == filename
    assert obj["format"] == 1
    assert obj["function_total"] == 0

    # No entities
    assert not obj["data"]

    # Just verify that we set some value for the timestamp.
    assert isinstance(obj["timestamp"], float)


def test_serialize_address():
    """Serialized addresses are lowercase hex with the "0x" prefix and no padding digits."""
    addr = 0x40A000
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[addr] = ReccmpComparedEntity(
        orig_addr=addr, name="test", accuracy=1.0, recomp_addr=addr
    )

    obj = json.loads(serialize_reccmp_report(report))
    [entity] = obj["data"]

    assert entity["address"] == "0x40a000"
    assert entity["recomp"] == "0x40a000"


def test_serialize_address_uses_dict_key():
    """The dict key is the source of truth for the orig addr.
    The value on the entity is redundant and is not serialized."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x200, name="test", accuracy=1.0, recomp_addr=0x100
    )

    obj = json.loads(serialize_reccmp_report(report))
    [entity] = obj["data"]
    assert entity["address"] == "0x100"


def test_serialize_prefer_existing_udiff():
    """Do not recreate the unified diff if the entity already has one."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x100,
        name="test",
        accuracy=1.0,
        recomp_addr=0x100,
        rdiff=sample_rdiff(),
        udiff=sample_udiff(),
    )

    text = serialize_reccmp_report(report, diff_included=True)
    obj = json.loads(text)
    [entity] = obj["data"]

    # Crude, but verifies that we are not using the data from sample_rdiff().
    assert entity["diff"]
    assert "nop" in str(entity["diff"])


def test_serialize_excludes_defaults():
    """Any fields set to a default value are omitted. This is to save space."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x100, name="test", accuracy=1.0, recomp_addr=0x100
    )

    obj = json.loads(serialize_reccmp_report(report))
    [entity] = obj["data"]

    assert entity["address"] == "0x100"
    assert entity["recomp"] == "0x100"

    # The remaining optional fields are not in the JSON.
    assert "stub" not in entity
    assert "library" not in entity
    assert "effective" not in entity
    assert "diff" not in entity
    assert "type" not in entity


def test_serialize_existing_timestamp():
    """Serialize the timestamp captured when the report object was created.
    Do not use a new timestamp when preparing the JSON string."""
    then = datetime(2000, 1, 1)
    report = ReccmpStatusReport(filename="test.exe", timestamp=then)

    obj = json.loads(serialize_reccmp_report(report))
    assert obj["timestamp"] == then.timestamp()

    # Should not alter report
    assert report.timestamp == then


def test_serialize_updates_function_total():
    """Recalculate the function count before serializing."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x100, name="test", accuracy=1.0, recomp_addr=0x100
    )
    assert report.function_total == 0

    obj = json.loads(serialize_reccmp_report(report))

    assert report.function_total == 1
    assert obj["function_total"] == 1


def test_serialize_recomp_addr_various():
    """An entity created with `reccmp-aggregate` that does not have
    a fixed recomp addr should use the magic string `various`."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x100, name="test", accuracy=1.0, recomp_addr_various=True
    )

    obj = json.loads(serialize_reccmp_report(report))
    [entity] = obj["data"]
    assert entity["recomp"] == "various"


def test_serialize_omits_unmatched_entities():
    """Version 1 reports contain only matched entities."""
    report = ReccmpStatusReport(filename="test.exe")
    report.entities[0x100] = ReccmpComparedEntity(
        orig_addr=0x100, name="test", accuracy=1.0
    )

    obj = json.loads(serialize_reccmp_report(report))
    assert not obj["data"]

    # The unmatched entity is still counted for the function total.
    assert obj["function_total"] == 1
