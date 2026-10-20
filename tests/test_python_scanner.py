from ai_project_scanner.python_scanner import scan_python_file


def test_scan_python_file_parses_valid_python(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("value = 1\nprint(value)\n")

    result = scan_python_file(path)

    assert result.ok
    assert result.results == []
    assert result.errors == []


def test_invalid_python_is_an_analysis_error(tmp_path):
    path = tmp_path / "invalid.py"
    path.write_text("def unfinished(\n")

    result = scan_python_file(path)

    assert not result.ok
    assert not result.findings
    assert result.errors[0].startswith("Cannot parse Python source:")


def test_unreadable_python_file_is_an_analysis_error(tmp_path):
    result = scan_python_file(tmp_path / "missing.py")

    assert not result.ok
    assert result.errors[0].startswith("Cannot read file:")


def test_unknown_source_encoding_is_an_analysis_error(tmp_path):
    path = tmp_path / "invalid_encoding.py"
    path.write_text("# coding: unknown-encoding\nvalue = 1\n")

    result = scan_python_file(path)

    assert not result.ok
    assert result.errors[0].startswith("Cannot parse Python source:")


def test_scan_python_file_does_not_execute_source(tmp_path):
    marker = tmp_path / "executed"
    path = tmp_path / "source.py"
    path.write_text(f"open({str(marker)!r}, 'w')\n")

    result = scan_python_file(path)

    assert result.ok
    assert result.results == []
    assert not marker.exists()


def test_local_deserialization_detected_through_import_aliases(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(
        "import pickle as p\n"
        "from joblib import load as load_artifact\n"
        "p.load(file)\n"
        "p.loads(data)\n"
        "load_artifact(path)\n"
    )

    result = scan_python_file(path)

    assert [finding.rule_id for finding in result.findings] == [
        "python.unsafe_deserialization",
        "python.unsafe_deserialization",
        "python.unsafe_deserialization",
    ]
    assert [finding.evidence[0].attributes["api"] for finding in result.findings] == [
        "pickle.load",
        "pickle.loads",
        "joblib.load",
    ]
    assert [finding.evidence[0].location for finding in result.findings] == [
        "line 3, column 1",
        "line 4, column 1",
        "line 5, column 1",
    ]
    assert all(
        finding.evidence[0].attributes["operation"]
        == "local artifact deserialization"
        for finding in result.findings
    )


def test_model_acquisition_and_remote_code_trust_are_distinct(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(
        "from transformers import AutoModel as Model\n"
        "model = Model.from_pretrained('org/model', trust_remote_code=True)\n"
    )

    result = scan_python_file(path)

    [acquisition] = [
        evidence for evidence in result.evidence
        if evidence.attributes["operation"] == "remote model acquisition"
    ]
    [trust] = result.findings
    assert acquisition.attributes["api"] == "transformers.AutoModel.from_pretrained"
    assert acquisition.location == "line 2, column 9"
    assert trust.rule_id == "python.remote_code_trust"
    assert trust.evidence[0].attributes["trust_remote_code"] is True
    assert trust.evidence[0].attributes["api"] == acquisition.attributes["api"]


def test_dataset_prompt_and_artifact_acquisition_are_informational(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(
        "from datasets import load_dataset as dataset\n"
        "from langchain import hub as prompt_hub\n"
        "import huggingface_hub as hf\n"
        "dataset('org/data')\n"
        "prompt_hub.pull('org/prompt')\n"
        "hf.hf_hub_download('org/model', 'config.json')\n"
    )

    result = scan_python_file(path)

    assert not result.findings
    assert [e.attributes["operation"] for e in result.evidence] == [
        "external dataset acquisition",
        "external prompt acquisition",
        "remote artifact acquisition",
    ]
    assert [e.attributes["api"] for e in result.evidence] == [
        "datasets.load_dataset",
        "langchain.hub.pull",
        "huggingface_hub.hf_hub_download",
    ]
    assert [e.attributes["line"] for e in result.evidence] == [4, 5, 6]


def test_similarly_named_unimported_methods_are_not_detected(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(
        "model.from_pretrained('local')\n"
        "dataset.load_dataset('local')\n"
        "prompt.pull('local')\n"
        "from unrelated import AutoModel, load_dataset\n"
        "AutoModel.from_pretrained('local')\n"
        "load_dataset('local')\n"
    )

    result = scan_python_file(path)

    assert result.ok
    assert not result.results


def test_remote_code_requires_explicit_true(tmp_path):
    path = tmp_path / "source.py"
    path.write_text(
        "from transformers import AutoModel\n"
        "AutoModel.from_pretrained('org/model', trust_remote_code=False)\n"
        "AutoModel.from_pretrained('org/model', trust_remote_code=enabled)\n"
    )

    result = scan_python_file(path)

    assert not result.findings
    assert len(result.evidence) == 2
