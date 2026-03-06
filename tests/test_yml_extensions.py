"""Testing custom validators/serializers for pydantic models."""

from pathlib import Path
from io import StringIO
from pydantic import BaseModel
import ruamel.yaml
from reccmp.project.yml_extensions import PathSequence


_yaml = ruamel.yaml.YAML()


def dump_model_to_yml_string(model: BaseModel):
    """Shim for producing a YML string from the model.
    Ruamel only outputs to a buffer (file)."""
    with StringIO() as buf:
        data = model.model_dump(mode="json")
        _yaml.dump(data=data, stream=buf)
        return buf.getvalue()


def test_path_sequence():
    """Demonstrating the expected output of the PathSequence pydantic type."""

    class Test(BaseModel):
        paths: PathSequence = tuple()

    single_path = (Path("hello"),)
    multi_path = (Path("hello"), Path("test"))

    # Should output a string if the tuple has one entry.
    assert dump_model_to_yml_string(Test(paths=single_path)) == "paths: hello\n"

    # Should use multi-line array if the tuple has 2+ entries.
    assert (
        dump_model_to_yml_string(Test(paths=multi_path)) == "paths:\n- hello\n- test\n"
    )

    # Should use inline array if the tuple has no entries
    assert dump_model_to_yml_string(Test(paths=())) == "paths: []\n"

    # Should use default value (here an empty tuple) if the key is unset
    assert dump_model_to_yml_string(Test()) == "paths: []\n"
