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
                                "kind": "FieldDecl",
                                "name": "value",
                                "type": {"qualType": "int"},
                                "loc": {"file": str(source), "line": 6},
                            },
                            {
                                "id": "run",
                                "kind": "CXXMethodDecl",
                                "name": "Run",
                                "mangledName": "?Run@Widget@N@@UAEHF@Z",
                                "parentDeclContextId": "widget",
                                "type": {
                                    "qualType": "int (short) __attribute__((thiscall))"
                                },
                                "loc": {"file": str(source), "line": 7},
                                "range": {"end": {"file": str(source), "line": 7}},
                                "inner": [
                                    {"kind": "OverrideAttr"},
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
    assert [(field.name, field.type) for field in index.classes[0].fields] == [("value", "int")]
    assert index.classes[0].vtable_address == 0x2000


def test_source_index_records_isle_style_base_vtables(tmp_path: Path) -> None:
    source = tmp_path / "sample.cpp"
    source.write_text(
        "class Primary {};\n"
        "class Secondary {};\n"
        "// VTABLE: TEST 0x2000 Widget\n"
        "// VTABLE: TEST 0x2100 Secondary\n"
        "class Widget : public Primary, public Secondary {};\n",
        encoding="utf-8",
    )
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "id": "widget",
                "kind": "CXXRecordDecl",
                "name": "Widget",
                "completeDefinition": True,
                "loc": {"file": str(source), "line": 5},
                "range": {"end": {"file": str(source), "line": 5}},
                "bases": [
                    {"type": {"qualType": "Primary"}},
                    {"type": {"qualType": "Secondary"}},
                ],
            }
        ],
    }

    index = SourceIndex.from_ast_documents(tmp_path, "TEST", [source], [(ast, source)])

    assert len(index.classes) == 1
    assert index.classes[0].vtable_address == 0x2000
    assert [(item.address, item.base_class) for item in index.classes[0].base_vtables] == [
        (0x2100, "Secondary")
    ]


def test_source_index_preserves_template_specialization_owner(tmp_path: Path) -> None:
    source = tmp_path / "vector.cpp"
    source.write_text(
        "// FUNCTION: TEST 0x3000\n"
        "template<> Vec<float>* Vec<float>::Convert(double) { return this; }\n",
        encoding="utf-8",
    )
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "id": "vec-float",
                "kind": "ClassTemplateSpecializationDecl",
                "name": "Vec",
                "inner": [
                    {"kind": "TemplateArgument", "type": {"qualType": "float"}},
                    {
                        "kind": "CXXMethodDecl",
                        "name": "Convert",
                        "mangledName": "?Convert@?$Vec@M@@QAEPAV1@N@Z",
                        "parentDeclContextId": "vec-float",
                        "type": {"qualType": "Vec<float> *(double)"},
                        "loc": {"file": str(source), "line": 2},
                        "range": {"begin": {"file": str(source), "line": 2}},
                        "inner": [
                            {"kind": "ParmVarDecl", "type": {"qualType": "double"}},
                            {"kind": "CompoundStmt"},
                        ],
                    },
                ],
            }
        ],
    }

    index = SourceIndex.from_ast_documents(tmp_path, "TEST", [source], [(ast, source)])

    declaration = index.markers[0].declaration
    assert declaration is not None
    assert declaration.qualified_name == "Vec<float>::Convert"
    assert declaration.owning_class == "Vec<float>"


def test_source_index_joins_standalone_template_vtable_by_name(tmp_path: Path) -> None:
    source = tmp_path / "vector.cpp"
    source.write_text(
        "template<class T> class Vec {};\n"
        "// VTABLE: TEST 0x2000\n"
        "// class Vec<float>\n",
        encoding="utf-8",
    )
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "id": "vec-float",
                "kind": "ClassTemplateSpecializationDecl",
                "name": "Vec",
                "completeDefinition": True,
                "loc": {"file": str(source), "line": 1},
                "range": {"end": {"file": str(source), "line": 1}},
                "inner": [
                    {"kind": "TemplateArgument", "type": {"qualType": "float"}}
                ],
            }
        ],
    }

    index = SourceIndex.from_ast_documents(tmp_path, "TEST", [source], [(ast, source)])

    assert len(index.classes) == 1
    assert index.classes[0].qualified_name == "Vec<float>"
    assert index.classes[0].vtable_address == 0x2000


def test_source_index_preserves_standalone_template_vtable_without_ast_record(
    tmp_path: Path,
) -> None:
    source = tmp_path / "vector.cpp"
    source.write_text(
        "// VTABLE: TEST 0x2000\n"
        "// class Vec<float>\n",
        encoding="utf-8",
    )
    ast = {"kind": "TranslationUnitDecl"}

    index = SourceIndex.from_ast_documents(tmp_path, "TEST", [source], [(ast, source)])

    assert len(index.classes) == 1
    assert index.classes[0].semantic_id == "record:Vec<float>"
    assert index.classes[0].qualified_name == "Vec<float>"
    assert index.classes[0].source_file == "vector.cpp"
    assert index.classes[0].vtable_address == 0x2000


def test_source_index_combines_distinct_marker_targets(tmp_path: Path) -> None:
    first = tmp_path / "first.cpp"
    second = tmp_path / "second.cpp"
    first.write_text("// FUNCTION: FIRST 0x1000\nvoid One() {}\n", encoding="utf-8")
    second.write_text("// FUNCTION: SECOND 0x2000\nvoid Two() {}\n", encoding="utf-8")
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "One",
                "mangledName": "?One@@YAXXZ",
                "type": {"qualType": "void ()"},
                "loc": {"file": str(first), "line": 2},
                "inner": [{"kind": "CompoundStmt"}],
            },
            {
                "kind": "FunctionDecl",
                "name": "Two",
                "mangledName": "?Two@@YAXXZ",
                "type": {"qualType": "void ()"},
                "loc": {"file": str(second), "line": 2},
                "inner": [{"kind": "CompoundStmt"}],
            },
        ],
    }

    index = SourceIndex.from_ast_documents_targets(
        tmp_path,
        {"FIRST": [first], "SECOND": [second]},
        [(ast, first)],
    )

    assert [(marker.address, marker.declaration.qualified_name) for marker in index.markers] == [
        (0x1000, "One"),
        (0x2000, "Two"),
    ]
