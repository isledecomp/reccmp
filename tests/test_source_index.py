from pathlib import Path

from reccmp.source import SourceIndex


def test_source_index_joins_markers_to_clang_semantics(tmp_path: Path) -> None:
    source = tmp_path / "sample.cpp"
    source.write_text(
        "namespace N {\n"
        "class Base {};\n"
        "// VTABLE: TEST 0x2000\n"
        "class Widget : public Base {\n"
        "public:\n"
        "  // FUNCTION: TEST 0x1000\n"
        "  virtual int Run(short value) { return value; }\n"
        "};\n"
        "}\n",
        encoding="utf-8",
    )
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "id": "ns",
                "kind": "NamespaceDecl",
                "name": "N",
                "inner": [
                    {"id": "base", "kind": "CXXRecordDecl", "name": "Base"},
                    {
                        "id": "widget",
                        "kind": "CXXRecordDecl",
                        "name": "Widget",
                        "completeDefinition": True,
                        "loc": {"file": str(source), "line": 4},
                        "range": {"end": {"file": str(source), "line": 8}},
                        "bases": [{"type": {"qualType": "N::Base"}}],
                        "inner": [
                            {
                                "id": "run",
                                "kind": "CXXMethodDecl",
                                "name": "Run",
                                "mangledName": "?Run@Widget@N@@UAEHF@Z",
                                "parentDeclContextId": "widget",
                                "virtual": True,
                                "type": {
                                    "qualType": "int (short) __attribute__((thiscall))"
                                },
                                "loc": {"file": str(source), "line": 7},
                                "range": {"end": {"file": str(source), "line": 7}},
                                "inner": [
                                    {
                                        "kind": "ParmVarDecl",
                                        "type": {"qualType": "short"},
                                    },
                                    {"kind": "CompoundStmt"},
                                ],
                            }
                        ],
                    },
                ],
            }
        ],
    }

    index = SourceIndex.from_ast_documents(tmp_path, "TEST", [source], [(ast, source)])

    assert len(index.markers) == 1
    declaration = index.markers[0].declaration
    assert declaration is not None
    assert declaration.qualified_name == "N::Widget::Run"
    assert declaration.semantic_kind == "instance_method"
    assert declaration.calling_convention == "__thiscall"
    assert declaration.parameter_types == ("short",)
    assert declaration.owning_class == "N::Widget"
    assert declaration.is_virtual
    assert index.classes[0].bases == ("N::Base",)
    assert index.classes[0].vtable_address == 0x2000
