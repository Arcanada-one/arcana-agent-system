"""Focused controls for explicit source-input declarations and graph bindings."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema
import build_graph
import impact_pair
import source_input_contract as sic
import verify


# Retained as a bounded candidate input supplied for the later consumer feature.
# The source and consumer SHA-256 values were not supplied, so this record is not
# a live SourceInputContract/v1 declaration and cannot claim the other 53 paths.
FI10_PR1_CANDIDATE = {
    "repo": "fi10-atlas",
    "pull_request": 1,
    "commit": "bb05641abdc58835cc9d9a6a0ec5a40230ee8975",
    "source_path": "sources/04_registry/SOURCE_INPUT_ARCHIVE_HASHES.json",
    "consumer_path": "tools/verify_archive_extractions.py",
    "positive_argv": ["python3", "tools/verify_archive_extractions.py"],
    "negative_argv": ["python3", "tools/verify_manifest_negative_control.py"],
    "positive_behavior": "validates schema, accepted two names, archive IDs, pins and byte counts before extracting 2016 members",
    "negative_behavior": "mutates the registry digest in a disposable copy and requires the same validator's exact pin-mismatch refusal",
    "covered_scope": "this registry category only",
    "unbound_scope": "the remaining 53 changed paths and Atlas54",
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


SUPPORTED_PYTHON = Path(sys.executable).resolve()
# setup-python exposes the selected runtime as `python3`; the verifier pins the
# resolved running executable above and resolves that same command in its control environment.
SUPPORTED_PYTHON_COMMAND = "python3"

CONSUMER_SOURCE = b'''from pathlib import Path
import json

def validate_fixture_schema(value, schema):
    # This fixture deliberately implements only the object/integer and null schema shapes below.
    expected = schema.get("type")
    if expected == "null":
        valid = value is None
    elif expected == "object":
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        valid = isinstance(value, dict) and all(key in value for key in required)
        if valid:
            for key, rule in properties.items():
                if key in value and rule.get("type") == "integer" and type(value[key]) is not int:
                    valid = False
                    break
    else:
        valid = False
    if not valid:
        raise ValueError("schema rejected committed input")

def load_source():
    value = json.loads((Path(__file__).resolve().parents[2] / "fixtures/i10/sample-digests/input/projection.json").read_text())
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas/DecimalProjection.v1.json").read_text())
    validate_fixture_schema(value, schema)
    return value

if __name__ == "__main__":
    print("positive", json.dumps(load_source(), sort_keys=True))
'''

CONTROL_SOURCE = b'''from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
consumer = root / "fixtures/i10/run_controls.py"
input_source = root / "fixtures/i10/sample-digests/input/projection.json"
schema_source = root / "schemas/DecimalProjection.v1.json"
if "--negative-missing" in sys.argv:
    with tempfile.TemporaryDirectory() as directory:
        missing_root = Path(directory)
        (missing_root / "fixtures/i10").mkdir(parents=True)
        (missing_root / "schemas").mkdir()
        shutil.copyfile(consumer, missing_root / "fixtures/i10/run_controls.py")
        shutil.copyfile(schema_source, missing_root / "schemas/DecimalProjection.v1.json")
        result = subprocess.run([sys.executable, str(missing_root / "fixtures/i10/run_controls.py")],
                                capture_output=True, text=True)
        assert result.returncode != 0 and "FileNotFoundError" in result.stderr
        print("refused: missing source input")
elif "--negative-poison-schema" in sys.argv:
    with tempfile.TemporaryDirectory() as directory:
        poisoned_root = Path(directory)
        (poisoned_root / "fixtures/i10/sample-digests/input").mkdir(parents=True)
        (poisoned_root / "schemas").mkdir()
        shutil.copyfile(consumer, poisoned_root / "fixtures/i10/run_controls.py")
        shutil.copyfile(input_source, poisoned_root / "fixtures/i10/sample-digests/input/projection.json")
        (poisoned_root / "schemas/DecimalProjection.v1.json").write_text('{"type":"null"}\\n')
        result = subprocess.run([sys.executable, str(poisoned_root / "fixtures/i10/run_controls.py")],
                                capture_output=True, text=True)
        assert (result.returncode != 0 and
                "ValueError: schema rejected committed input" in result.stderr), result.stderr
        print("refused: schema rejected committed input")
else:
    result = subprocess.run([sys.executable, str(consumer)], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.startswith("positive ")
    print("positive: committed consumer read")
'''

INPUT_PATH = "fixtures/i10/sample-digests/input/projection.json"
SCHEMA_PATH = "schemas/DecimalProjection.v1.json"
CONSUMER_PATH = "fixtures/i10/run_controls.py"
CONTROL_PATH = "tests/control.py"
SCHEMA_SOURCE = b'{"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}\n'


def make_contract(source: bytes, consumer: bytes, control: bytes | None = None,
                  schema: bytes = SCHEMA_SOURCE) -> dict:
    control = CONTROL_SOURCE if control is None else control
    control_path = CONTROL_PATH
    common_sources = {CONSUMER_PATH: digest(consumer), control_path: digest(control)}
    inputs = []
    for source_path, source_bytes in ((INPUT_PATH, source), (SCHEMA_PATH, schema)):
        inputs.append({
            "source_path": source_path,
            "source_sha256": digest(source_bytes),
            "consumer_path": CONSUMER_PATH,
            "consumer_sha256": digest(consumer),
            "control_sources": common_sources,
            "controls": [
                {"id": "positive", "role": "positive", "execution_path": control_path,
                 "execution_sha256": digest(control), "argv": [SUPPORTED_PYTHON_COMMAND, control_path], "cwd": ".",
                 "interpreter": SUPPORTED_PYTHON_COMMAND, "interpreter_sha256": "a" * 64,
                 "environment": {"CI": "1"}, "timeout_seconds": 120,
                 "expected_exit_code": 0, "expected_output_contains": "positive"},
                {"id": "negative-missing", "role": "negative", "execution_path": control_path,
                 "execution_sha256": digest(control), "argv": [SUPPORTED_PYTHON_COMMAND, control_path, "--negative-missing"],
                 "cwd": ".", "interpreter": SUPPORTED_PYTHON_COMMAND, "interpreter_sha256": "a" * 64,
                 "environment": {"CI": "1"}, "timeout_seconds": 120,
                 "expected_exit_code": 0, "expected_output_contains": "refused: missing source input"},
                {"id": "negative-poison-schema", "role": "negative", "execution_path": control_path,
                 "execution_sha256": digest(control),
                 "argv": [SUPPORTED_PYTHON_COMMAND, control_path, "--negative-poison-schema"], "cwd": ".",
                 "interpreter": SUPPORTED_PYTHON_COMMAND, "interpreter_sha256": "a" * 64,
                 "environment": {"CI": "1"}, "timeout_seconds": 120,
                 "expected_exit_code": 0,
                 "expected_output_contains": "refused: schema rejected committed input"},
            ],
        })
    return {
        "schema": sic.SCHEMA,
        "inputs": inputs,
    }


class SourceInputContractTests(unittest.TestCase):
    def setUp(self):
        self.source = b'{"value":3}\n'
        self.schema = SCHEMA_SOURCE
        self.consumer = CONSUMER_SOURCE
        self.control = CONTROL_SOURCE
        self.manifest = make_contract(self.source, self.consumer, schema=self.schema)
        self.raw = (json.dumps(self.manifest, separators=(",", ":")) + "\n").encode()
        self.files = {INPUT_PATH: self.source, SCHEMA_PATH: self.schema, CONSUMER_PATH: self.consumer,
                      CONTROL_PATH: self.control, sic.MANIFEST_PATH: self.raw}

    def _parse_with_consumer(self, consumer: bytes):
        files = dict(self.files)
        files[CONSUMER_PATH] = consumer
        doc = json.loads(self.raw)
        for entry in doc["inputs"]:
            entry["consumer_sha256"] = digest(consumer)
            entry["control_sources"][CONSUMER_PATH] = digest(consumer)
        raw = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
        files[sic.MANIFEST_PATH] = raw
        return sic.parse(raw, files)

    def test_explicit_positive_and_negative_controls_bind_every_file_and_runtime_field(self):
        entries = sic.parse(self.raw, self.files,
                            {path: "100644" for path in self.files})
        self.assertEqual(INPUT_PATH, entries[0]["source_path"])
        self.assertEqual({"positive", "negative"}, {c["role"] for c in entries[0]["controls"]})
        self.assertEqual(".", entries[0]["controls"][0]["cwd"])

    def test_manifest_matches_the_committed_source_input_schema(self):
        schema_path = Path(__file__).resolve().parents[2] / "contracts/graph-verified-change/source-input-contract.v1.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(self.manifest)

    def test_missing_input_consumer_control_or_nonregular_file_fails_closed(self):
        for path in (INPUT_PATH, SCHEMA_PATH, CONSUMER_PATH, CONTROL_PATH):
            with self.subTest(path=path):
                with self.assertRaisesRegex(sic.ContractError, "missing"):
                    sic.parse(self.raw, {k: v for k, v in self.files.items() if k != path})
        with self.assertRaisesRegex(sic.ContractError, "regular Git file"):
            sic.parse(self.raw, self.files, {path: "120000" for path in self.files})

    def test_wrong_source_consumer_and_control_pins_refuse(self):
        wrong = dict(self.files)
        wrong[INPUT_PATH] = b"{}"
        with self.assertRaisesRegex(sic.ContractError, "bytes differ"):
            sic.parse(self.raw, wrong)
        wrong = dict(self.files)
        wrong[SCHEMA_PATH] = b'{"type":"null"}\n'
        with self.assertRaisesRegex(sic.ContractError, "bytes differ"):
            sic.parse(self.raw, wrong)
        wrong = dict(self.files)
        wrong[CONSUMER_PATH] += b"# changed\n"
        with self.assertRaisesRegex(sic.ContractError, "bytes differ"):
            sic.parse(self.raw, wrong)
        wrong = dict(self.files)
        wrong[CONTROL_PATH] += b"# changed\n"
        with self.assertRaisesRegex(sic.ContractError, "bytes differ"):
            sic.parse(self.raw, wrong)

    def test_consumer_requires_literal_declared_read_and_refuses_dynamic_or_unbound_reads(self):
        for consumer, message in (
            (b"def consume(): return 1\n", "no statically bound literal read"),
            (CONSUMER_SOURCE + b"\nopen(selected_path).read()\n", "unresolved dynamic"),
            (CONSUMER_SOURCE + b"\nopen('schemas/other.json').read()\n", "unbound literal"),
        ):
            with self.subTest(message=message):
                files = dict(self.files)
                files[CONSUMER_PATH] = consumer
                doc = json.loads(self.raw)
                for entry in doc["inputs"]:
                    entry["consumer_sha256"] = digest(consumer)
                    entry["control_sources"][CONSUMER_PATH] = digest(consumer)
                raw = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
                files[sic.MANIFEST_PATH] = raw
                with self.assertRaisesRegex(sic.ContractError, message):
                    sic.parse(raw, files)

    def test_pathlib_constructor_requires_unambiguous_direct_pathlib_import(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        fake_path_consumer = (CONSUMER_SOURCE.replace(b"from pathlib import Path", b"from pathlib import Path as SafePath")
                              .replace(b"Path(", b"SafePath(")
                              + f"\ndef Path(value): return FakePath(value)\nPath('{pinned}').read_text()\n".encode())
        cases = (
            fake_path_consumer,
            f"\nfrom pathlib import Path as SourcePath\nSourcePath = FakePath\nSourcePath('{pinned}').read_text()\n".encode(),
            f"\nfrom pathlib import Path as SourcePath\ndef consume(SourcePath): SourcePath('{pinned}').read_text()\n".encode(),
            f"\nfrom pathlib import Path as SourcePath\nSourcePath = FakePath\n"
            f"(SourcePath(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\nfrom pathlib import Path as SourcePath\ndef consume(SourcePath):\n"
            f"    (SourcePath(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\nfrom pathlib import Path as SourcePath\nfor SourcePath in [FakePath]: SourcePath('{pinned}').read_text()\n".encode(),
            f"\nfrom pathlib import Path as SourcePath\nwith fake_factory() as SourcePath: SourcePath('{pinned}').read_text()\n".encode(),
            f"\nimport pathlib as path_api\npath_api.Path('{pinned}').read_text()\n".encode(),
            f"\nimport pathlib as path_api\n"
            f"(path_api.Path(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\nimport pathlib as path_api\npath_api.Path = FakePath\npath_api.Path('{pinned}').read_text()\n".encode(),
        )
        for consumer in cases:
            with self.subTest(consumer=consumer[-100:]):
                with self.assertRaises(sic.ContractError):
                    self._parse_with_consumer(consumer)

    def test_pathlib_alias_import_remains_a_supported_literal_constructor(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        extra = (f"\nfrom pathlib import Path as SourcePath\n"
                 f"(SourcePath(__file__).resolve().parents[2] / '{pinned}').read_text()\n").encode()
        self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_untouched_file_anchor_remains_a_supported_literal_path(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        consumer = (CONSUMER_SOURCE +
                    "\n(Path(__file__).parent / 'sample-digests/input/projection.json').read_text()\n".encode())
        reads, unresolved = sic.literal_source_reads(CONSUMER_PATH, consumer)
        self.assertFalse(unresolved)
        self.assertIn(pinned, {row["path"] for row in reads})

    def test_rebound_or_shadowed_file_anchor_cannot_attribute_pinned_paths(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        cases = (
            f"\n__file__ = 'elsewhere.py'\n(Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\ndef consume(__file__):\n    (Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\nleft, __file__ = ('x', 'elsewhere.py')\n"
            f"(Path(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\nfor __file__ in ['elsewhere.py']:\n"
            f"    (Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\nwith fake_file() as __file__:\n"
            f"    (Path(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\nimport pathlib as __file__\n"
            f"(Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\nfrom unknown_runtime import *\n"
            f"(Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\ndef __file__(): return 'elsewhere.py'\n"
            f"(Path(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode(),
            f"\ntry:\n    pass\nexcept Exception as __file__:\n"
            f"    (Path(__file__).parent / '{pinned}').read_text()\n".encode(),
            f"\ndel __file__\n(Path(__file__).parent / '{pinned}').read_text()\n".encode(),
        )
        for extra in cases:
            with self.subTest(extra=extra):
                consumer = CONSUMER_SOURCE + extra
                reads, unresolved = sic.literal_source_reads(CONSUMER_PATH, consumer)
                self.assertTrue(unresolved)
                self.assertNotIn(pinned, {row["path"] for row in reads})
                with self.assertRaises(sic.ContractError):
                    self._parse_with_consumer(consumer)

    def test_file_io_methods_require_a_compatible_path_object_receiver(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        positive = (CONSUMER_SOURCE +
                    f"\n(Path(__file__).resolve().parents[2] / '{pinned}').read_text()\n".encode())
        reads, unresolved = sic.literal_source_reads(CONSUMER_PATH, positive)
        self.assertFalse(unresolved)
        self.assertIn(pinned, {row["path"] for row in reads})

        for receiver in (
            f"'{pinned}'.read_text()",
            f"'{pinned}'.read_bytes()",
            f"'{pinned}'.open()",
            f"PurePath('{pinned}').read_text()",
            f"PurePosixPath('{pinned}').read_bytes()",
        ):
            with self.subTest(receiver=receiver):
                consumer = CONSUMER_SOURCE + f"\n{receiver}\n".encode()
                reads, unresolved = sic.literal_source_reads(CONSUMER_PATH, consumer)
                self.assertEqual([receiver.split(".")[-1].split("(")[0]],
                                 [row["operation"] for row in unresolved])
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(consumer)

    def test_open_apis_count_only_provable_read_modes_and_os_flags(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        path_expr = f"Path(__file__).resolve().parents[2] / '{pinned}'"
        positive = (
            f"open('{pinned}')\n",
            f"open('{pinned}', 'rb')\n",
            f"open('{pinned}', mode='r')\n",
            f"from builtins import open as source_open\nsource_open('{pinned}', mode='rt')\n",
            f"from io import open as io_open\nio_open('{pinned}')\n",
            f"from io import open as io_open\nio_open('{pinned}', mode='rb')\n",
            f"({path_expr}).open()\n",
            f"({path_expr}).open('r')\n",
            f"({path_expr}).open(mode='rb')\n",
            f"import os as os_api\nos_api.open('{pinned}', 0)\n",
            f"import os as os_api\nos_api.open('{pinned}', flags=os_api.O_RDONLY)\n",
            f"from os import open as os_open\nos_open('{pinned}', flags=0)\n",
        )
        for extra in positive:
            with self.subTest(extra=extra):
                self._parse_with_consumer(CONSUMER_SOURCE + extra.encode())

        negative = (
            f"open('{pinned}', 'w')\n",
            f"open('{pinned}', 'r+')\n",
            f"open('{pinned}', 'w+')\n",
            f"open('{pinned}', 'a+')\n",
            f"open('{pinned}', 'x+')\n",
            f"open('{pinned}', mode='a')\n",
            f"open('{pinned}', mode='r+')\n",
            f"open('{pinned}', mode='w+')\n",
            f"open('{pinned}', mode=selected_mode)\n",
            f"from builtins import open as source_open\nsource_open('{pinned}', mode='x')\n",
            f"from builtins import open as source_open\nsource_open('{pinned}', 'r+')\n",
            f"open('{pinned}', 'r', opener=custom_opener)\n",
            f"open('{pinned}', 'r', **open_options)\n",
            f"open(*open_args)\n",
            # The eighth positional open argument is the redirection-capable
            # opener; unsupported positional signatures are unresolved.
            f"open('{pinned}', 'r', -1, None, None, None, True, custom_opener)\n",
            f"({path_expr}).open('w')\n",
            f"({path_expr}).open('w+')\n",
            f"({path_expr}).open(mode='r+')\n",
            f"({path_expr}).open('r', opener=custom_opener)\n",
            f"({path_expr}).open(**open_options)\n",
            f"({path_expr}).open('r', None, None, None, None, None, custom_opener)\n",
            f"import io as io_api\nio_api.open('{pinned}', 'r', opener=custom_opener)\n",
            f"import io as io_api\nio_api.open('{pinned}', 'r', **open_options)\n",
            f"({path_expr}).open(mode=selected_mode)\n",
            f"import os as os_api\nos_api.open('{pinned}', os_api.O_WRONLY)\n",
            f"import os as os_api\nos_api.open('projection.json', 0, dir_fd=directory_fd)\n",
            f"import os as os_api\nos_api.open('projection.json', flags=0, dir_fd=directory_fd)\n",
            f"import os as os_api\nos_api.open('projection.json', 0, **open_options)\n",
            f"import os as os_api\nos_api.open('{pinned}', flags=selected_flags)\n",
            f"import os as os_api\nos_api.open('{pinned}', 1)\n",
            f"from os import open as os_open\nos_open('{pinned}', flags=selected_flags)\n",
        )
        for extra in negative:
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra.encode())

    def test_imported_and_assigned_open_aliases_cannot_hide_an_extra_literal_read(self):
        for extra in (
            b"\nfrom builtins import open as load\nload('schemas/other.json').read()\n",
            b"\nreader = open\nreader('schemas/other.json').read()\n",
            b"\nfrom builtins import open as load\nload = lambda path: None\nload('schemas/other.json').read()\n",
        ):
            with self.subTest(extra=extra):
                consumer = CONSUMER_SOURCE + extra
                files = dict(self.files)
                files[CONSUMER_PATH] = consumer
                doc = json.loads(self.raw)
                for entry in doc["inputs"]:
                    entry["consumer_sha256"] = digest(consumer)
                    entry["control_sources"][CONSUMER_PATH] = digest(consumer)
                raw = (json.dumps(doc, separators=(",", ":")) + "\n").encode()
                files[sic.MANIFEST_PATH] = raw
                with self.assertRaises(sic.ContractError):
                    sic.parse(raw, files)

    def test_real_imported_module_open_forms_remain_bound(self):
        for extra in (
            b"\nimport builtins as builtin_api\nbuiltin_api.open('fixtures/i10/sample-digests/input/projection.json').read()\n",
            b"\nimport os\nos.open('fixtures/i10/sample-digests/input/projection.json', 0)\n",
            b"\nimport io as io_api\nio_api.open('fixtures/i10/sample-digests/input/projection.json').read()\n",
            b"\nimport os as source_module\nreader = source_module\nreader.open('fixtures/i10/sample-digests/input/projection.json', 0)\n",
        ):
            with self.subTest(extra=extra):
                self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_unmutated_builtin_open_and_imported_builtin_open_remain_bound(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nopen('{pinned}').read()\n".encode(),
            f"\nfrom builtins import open as load\nload('{pinned}').read()\n".encode(),
            f"\nimport builtins as builtin_api\nbuiltin_api.open('{pinned}').read()\n".encode(),
        ):
            with self.subTest(extra=extra):
                self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_reassigned_imported_module_names_and_aliases_are_unresolved(self):
        for extra in (
            b"\nimport os\nos = object()\nos.open('fixtures/i10/sample-digests/input/projection.json', 0)\n",
            b"\nimport io as file_api\nfile_api = object()\nfile_api.open('fixtures/i10/sample-digests/input/projection.json').read()\n",
            b"\nimport builtins as builtin_api\nbuiltin_api = object()\nbuiltin_api.open('fixtures/i10/sample-digests/input/projection.json').read()\n",
            b"\nimport os as source_module\nreader = source_module\nsource_module = object()\nreader.open('fixtures/i10/sample-digests/input/projection.json', 0)\n",
            b"\nimport os as source_module\nsource_module = object()\nreader = source_module.open\nreader('fixtures/i10/sample-digests/input/projection.json', 0)\n",
            b"\nimport io as source_module\nsource_module = object()\nreader = source_module.open\nreader('fixtures/i10/sample-digests/input/projection.json').read()\n",
            b"\nimport builtins as source_module\nsource_module = object()\nreader = source_module.open\nreader('fixtures/i10/sample-digests/input/projection.json').read()\n",
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_reader_and_module_names_shadowed_by_function_or_lambda_parameters_are_unresolved(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nimport os\ndef consume(os): os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\ndef consume(os, /): os.open('{pinned}', 0)\n".encode(),
            f"\nfrom builtins import open as load\ndef consume(*, load): load('{pinned}').read()\n".encode(),
            f"\nimport os as path_api\ndef consume(*path_api): path_api.open('{pinned}', 0)\n".encode(),
            f"\nimport io as file_api\ndef consume(**file_api): file_api.open('{pinned}').read()\n".encode(),
            f"\nimport os\nconsume = lambda os: os.open('{pinned}', 0)\n".encode(),
            f"\nfrom builtins import open as load\nconsume = lambda load: load('{pinned}').read()\n".encode(),
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_reader_and_module_bindings_in_loop_with_and_exception_targets_are_unresolved(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nimport os\nfor os in [object()]: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nasync def consume(items):\n    async for os in items: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nwith object() as os: os.open('{pinned}', 0)\n".encode(),
            f"\nfrom builtins import open as load\nwith object() as load: load('{pinned}').read()\n".encode(),
            f"\nimport os\ntry: pass\nexcept Exception as os: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nleft, os = (object(), object())\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nleft, (os, other) = (object(), (object(), object()))\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nfor (left, os) in [(object(), object())]: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nmatch object():\n    case [left, os]: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nmatch object():\n    case {{'value': os, **rest}}: os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nmatch object():\n    case [*os]: os.open('{pinned}', 0)\n".encode(),
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_unsafe_loop_and_context_bindings_propagate_through_prior_aliases(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nimport os as source_module\nreader = source_module\nfor source_module in [object()]: pass\nreader.open('{pinned}', 0)\n".encode(),
            f"\nimport os as source_module\nreader = source_module\nwith object() as source_module: pass\nreader.open('{pinned}', 0)\n".encode(),
            f"\nfrom builtins import open as load\nreader = load\nfor load in [object()]: pass\nreader('{pinned}').read()\n".encode(),
            f"\nfrom builtins import open as load\nreader = load\nwith object() as load: pass\nreader('{pinned}').read()\n".encode(),
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_redefinitions_deletions_and_open_member_mutations_fail_closed(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nimport os\ndel os\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nimport fake as os\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nfrom builtins import open as os\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nos.open = fake_open\nos.open('{pinned}', 0)\n".encode(),
            f"\nimport os\ndef consume():\n    global os\n    os = object()\n    os.open('{pinned}', 0)\n".encode(),
            f"\nimport os\nif (os := object()): os.open('{pinned}', 0)\n".encode(),
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_builtin_open_mutation_invalidates_bare_and_captured_reader_aliases(self):
        pinned = "fixtures/i10/sample-digests/input/projection.json"
        for extra in (
            f"\nimport builtins\nbuiltins.open = fake_open\nopen('{pinned}').read()\n".encode(),
            f"\nimport builtins as builtin_api\nbuiltin_api.open = fake_open\nopen('{pinned}').read()\n".encode(),
            f"\nimport builtins\nreader = open\nbuiltins.open = fake_open\nreader('{pinned}').read()\n".encode(),
            f"\nimport builtins\nreader = builtins.open\nbuiltins.open = fake_open\nreader('{pinned}').read()\n".encode(),
            f"\nimport builtins\nbuiltins.open = fake_open\nreader = builtins.open\nreader('{pinned}').read()\n".encode(),
            f"\nfrom builtins import open as load\nreader = load\nimport builtins\nbuiltins.open = fake_open\nreader('{pinned}').read()\n".encode(),
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(sic.ContractError, "unresolved dynamic"):
                    self._parse_with_consumer(CONSUMER_SOURCE + extra)

    def test_unknown_fields_duplicate_members_and_partial_controls_refuse(self):
        doc = json.loads(self.raw)
        doc["unexpected"] = True
        with self.assertRaisesRegex(sic.ContractError, "unknown"):
            sic.parse(json.dumps(doc).encode())
        with self.assertRaisesRegex(sic.ContractError, "duplicate JSON member"):
            sic.parse(b'{"schema":"SourceInputContract/v1","schema":"SourceInputContract/v1","inputs":[]}')
        doc = json.loads(self.raw)
        doc["inputs"][0]["controls"] = doc["inputs"][0]["controls"][:1]
        with self.assertRaisesRegex(sic.ContractError, "controls"):
            sic.parse(json.dumps(doc).encode())

    def test_escaping_paths_shell_and_unrelated_unittest_module_refuse(self):
        doc = json.loads(self.raw)
        doc["inputs"][0]["source_path"] = "../outside.json"
        with self.assertRaisesRegex(sic.ContractError, "path"):
            sic.parse(json.dumps(doc).encode())
        doc = json.loads(self.raw)
        doc["inputs"][0]["controls"][0]["argv"] = [SUPPORTED_PYTHON_COMMAND, "-c", "print('positive')"]
        with self.assertRaisesRegex(sic.ContractError, "inline-code"):
            sic.parse(json.dumps(doc).encode())
        doc = json.loads(self.raw)
        doc["inputs"][0]["controls"][0]["argv"] = [
            SUPPORTED_PYTHON_COMMAND, "-m", "unittest", "unrelated.tests.Control.test_positive"]
        with self.assertRaisesRegex(sic.ContractError, "selectors"):
            sic.parse(json.dumps(doc).encode())

    def test_control_target_is_resolved_from_cwd_for_script_unittest_and_pytest(self):
        doc = json.loads(self.raw)
        entry = doc["inputs"][0]
        row = entry["controls"][0]
        row["cwd"] = "tools"
        row["argv"] = [SUPPORTED_PYTHON_COMMAND, "tests/control.py"]
        with self.assertRaisesRegex(sic.ContractError, "actual argv target differs"):
            sic.validate_control(row, entry, 0)

        row["argv"] = [SUPPORTED_PYTHON_COMMAND, "../tests/control.py"]
        self.assertEqual(CONTROL_PATH, sic.validate_control(row, entry, 0)[0])

        entry["control_sources"]["tools/tests/control.py"] = entry["control_sources"].pop(CONTROL_PATH)
        row.update({"execution_path": "tools/tests/control.py", "execution_sha256": digest(self.control),
                    "cwd": "tools", "argv": [SUPPORTED_PYTHON_COMMAND, "-m", "unittest",
                                               "tests.control.TestControl.test_positive"]})
        self.assertEqual("tools/tests/control.py", sic.validate_control(row, entry, 0)[0])
        row["argv"][-1] = "tools.tests.control.TestControl.test_positive"
        with self.assertRaisesRegex(sic.ContractError, "selectors do not bind"):
            sic.validate_control(row, entry, 0)

        row.update({"argv": [SUPPORTED_PYTHON_COMMAND, "-m", "pytest", "tests/control.py::TestControl::test_positive"]})
        self.assertEqual("tools/tests/control.py", sic.validate_control(row, entry, 0)[0])
        row["argv"] = [SUPPORTED_PYTHON_COMMAND, "-m", "pytest", "tests/control.py", "../tests/control.py"]
        with self.assertRaisesRegex(sic.ContractError, "pytest control form is unsupported"):
            sic.validate_control(row, entry, 0)

    def test_executor_refuses_cwd_decoy_before_starting_process(self):
        with tempfile.TemporaryDirectory(prefix="source-input-decoy-") as directory:
            root = Path(directory)
            target = root / CONTROL_PATH
            target.parent.mkdir(parents=True)
            target.write_text("print('pinned target')\n")
            decoy = root / "tools/tests/control.py"
            decoy.parent.mkdir(parents=True)
            decoy.write_text("print('decoy target')\n")
            interpreter = Path(sys.executable).resolve()
            row = {"interpreter": SUPPORTED_PYTHON_COMMAND, "interpreter_sha256": digest(interpreter.read_bytes()),
                   "cwd": "tools", "execution_path": CONTROL_PATH,
                   "execution_sha256": digest(target.read_bytes()),
                   "argv": [SUPPORTED_PYTHON_COMMAND, "tests/control.py"], "environment": {},
                   "timeout_seconds": 10, "expected_exit_code": 0,
                   "expected_output_contains": "pinned target"}
            runner = verify.Verify.__new__(verify.Verify)
            runner.exec_root = root
            with patch("verify.subprocess.Popen") as popen:
                result = runner._run_source_input_control(row)
            self.assertEqual("failed", result["state"])
            self.assertIn("argv target", result["reason"])
            popen.assert_not_called()

    def test_fi10_candidate_is_retained_but_not_promoted_without_byte_pins(self):
        self.assertEqual("bb05641abdc58835cc9d9a6a0ec5a40230ee8975", FI10_PR1_CANDIDATE["commit"])
        self.assertIn("verify_archive_extractions.py", FI10_PR1_CANDIDATE["positive_argv"][1])
        candidate = {"schema": sic.SCHEMA, "inputs": [{
            "source_path": FI10_PR1_CANDIDATE["source_path"],
            "consumer_path": FI10_PR1_CANDIDATE["consumer_path"],
        }]}
        with self.assertRaises(sic.ContractError):
            sic.parse(json.dumps(candidate).encode())

    def test_graph_binds_only_paths_named_in_the_explicit_manifest(self):
        files = dict(self.files)
        files["schemas/unlisted.json"] = b'{"unlisted":true}\n'
        tree = build_graph.Tree(files, {"file_modes": {p: "100644" for p in files}})
        builder = build_graph.Builder(tree, set(), build_graph.DEFAULT_WORK_ITEM_PATTERN)
        builder.base()
        edges = list(builder.g.edges.values())
        self.assertIn((f"code_unit:{CONSUMER_PATH}", "declares_source_input", f"code_unit:{INPUT_PATH}"),
                      {(e["from"], e["type"], e["to"]) for e in edges})
        self.assertIn((f"code_unit:{CONSUMER_PATH}", "reads_source_input", f"code_unit:{INPUT_PATH}"),
                      {(e["from"], e["type"], e["to"]) for e in edges})
        self.assertIn((f"code_unit:{CONSUMER_PATH}", "reads_source_input", f"code_unit:{SCHEMA_PATH}"),
                      {(e["from"], e["type"], e["to"]) for e in edges})
        self.assertNotIn("code_unit:schemas/unlisted.json", builder.g.nodes)
        self.assertIn("code_unit:.arcana/source-inputs.json", builder.g.nodes)

    def test_native_matrix_selects_literal_source_input_reader_and_source(self):
        with tempfile.TemporaryDirectory(prefix="source-input-selection-") as directory:
            root = Path(directory)
            for path, raw in self.files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Source Input Fixture"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "source-input@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "source input base"], check=True)
            base = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

            changed_source = b'{"value":4}\n'
            (root / INPUT_PATH).write_bytes(changed_source)
            manifest = json.loads(self.raw)
            manifest["inputs"][0]["source_sha256"] = digest(changed_source)
            (root / sic.MANIFEST_PATH).write_text(
                json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", INPUT_PATH, sic.MANIFEST_PATH], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "change declared source input"], check=True)
            head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

            repo = impact_pair.impact.Repo(root)
            before = impact_pair.index_at(repo, base)
            after = impact_pair.index_at(repo, head)
            changed_files = repo.diff_files(base, head)
            paired = impact_pair.query(before, after, changed_files, repo=repo, base=base, head=head,
                                       tree_commit=head, tree_dirty=False)
            required = impact_pair.mandatory_by_entity(before, after, paired)
            self.assertIn("source_input_contract", required[f"code_unit:{INPUT_PATH}"])
            self.assertIn("source_input_contract", required[f"code_unit:{CONSUMER_PATH}"])

    def test_executor_uses_pinned_interpreter_sanitized_environment_and_exact_oracle(self):
        with tempfile.TemporaryDirectory(prefix="source-input-control-") as directory:
            root = Path(directory)
            target = root / CONSUMER_PATH
            target.parent.mkdir(parents=True)
            target.write_text("import os\nprint('positive-control', os.getenv('SOURCE_INPUT_SECRET_SENTINEL', 'absent'))\n")
            interpreter = SUPPORTED_PYTHON
            row = {"interpreter": SUPPORTED_PYTHON_COMMAND, "interpreter_sha256": digest(interpreter.read_bytes()),
                   "cwd": ".", "execution_path": CONSUMER_PATH,
                   "execution_sha256": digest(target.read_bytes()),
                   "argv": [SUPPORTED_PYTHON_COMMAND, CONSUMER_PATH], "environment": {},
                   "timeout_seconds": 10, "expected_exit_code": 0,
                   "expected_output_contains": "positive-control absent"}
            runner = verify.Verify.__new__(verify.Verify)
            runner.exec_root = root
            with patch.dict("os.environ", {"SOURCE_INPUT_SECRET_SENTINEL": "should-not-inherit"}):
                result = runner._run_source_input_control(row)
            self.assertEqual("verified", result["state"])
            self.assertNotIn("should-not-inherit", result["stdout"])
            row["expected_output_contains"] = "different-oracle"
            self.assertEqual("failed", runner._run_source_input_control(row)["state"])

    def test_real_consumer_positive_and_missing_input_negative_keep_unbound_entity_not_measured(self):
        with tempfile.TemporaryDirectory(prefix="source-input-verifier-") as directory:
            root = Path(directory)
            files = dict(self.files)
            manifest = json.loads(self.raw)
            interpreter = SUPPORTED_PYTHON
            interpreter_sha = digest(interpreter.read_bytes())
            for entry in manifest["inputs"]:
                for control in entry["controls"]:
                    control["interpreter_sha256"] = interpreter_sha
            files[sic.MANIFEST_PATH] = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            for path, raw in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            runner = verify.Verify.__new__(verify.Verify)
            runner.entities = {
                f"code_unit:{INPUT_PATH}": {"required": {"source_input_contract"}},
                f"code_unit:{SCHEMA_PATH}": {"required": {"source_input_contract"}},
                "code_unit:schemas/unbound.json": {"required": {"source_input_contract"}},
            }
            runner.disabled = set()
            runner.tree_head = SimpleNamespace(
                files=files,
                meta={"file_modes": {path: "100644" for path in files}},
            )
            runner.exec_root = root
            runner.out_dir = root / "verifier-output"
            runner.out_dir.mkdir()
            runner.verifiers = []
            runner.ev = {}
            runner.v_source_input_contract()
            verdicts = runner.ev["v-source-input-contract"]
            detail = (runner.out_dir / "v-source-input-contract.json").read_text(encoding="utf-8")
            self.assertEqual("verified", verdicts[f"code_unit:{INPUT_PATH}"][0], detail)
            self.assertEqual("verified", verdicts[f"code_unit:{SCHEMA_PATH}"][0], repr(verdicts))
            self.assertEqual("not_measured", verdicts["code_unit:schemas/unbound.json"][0], repr(verdicts))

    def test_source_input_verifier_enabled_fault_and_disabled_control(self):
        with tempfile.TemporaryDirectory(prefix="source-input-selftest-calibration-") as directory:
            root = Path(directory)
            files = dict(self.files)
            manifest = json.loads(self.raw)
            interpreter_sha = digest(SUPPORTED_PYTHON.read_bytes())
            for entry in manifest["inputs"]:
                for control in entry["controls"]:
                    control["interpreter_sha256"] = interpreter_sha
            files[sic.MANIFEST_PATH] = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            for path, raw in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)

            entity = f"code_unit:{INPUT_PATH}"

            def observe(candidate_files, disabled=()):
                run_root = root / ("disabled" if disabled else "enabled")
                run_root.mkdir(exist_ok=True)
                runner = verify.Verify.__new__(verify.Verify)
                runner.needing = lambda verifier: [entity] if verifier == "source_input_contract" else []
                runner.entities = {entity: {"required": {"source_input_contract"}}}
                runner.disabled = set(disabled)
                runner.tree_head = SimpleNamespace(
                    files=candidate_files,
                    meta={"file_modes": {path: "100644" for path in candidate_files}},
                )
                runner.exec_root = root
                runner.out_dir = run_root
                runner.out_dir.mkdir(exist_ok=True)
                runner.verifiers = []
                runner.ev = {}
                runner.v_source_input_contract()
                return runner.ev["v-source-input-contract"][entity], runner.verifiers[-1]

            verified, _ = observe(files)
            self.assertEqual("verified", verified[0], verified[1])

            mutated = dict(files)
            mutated[INPUT_PATH] = b'{"value":"wrong-type"}\n'
            failed, _ = observe(mutated)
            self.assertEqual("failed", failed[0], failed[1])

            not_measured, row = observe(mutated, disabled=("source_input_contract",))
            self.assertEqual("not_measured", not_measured[0], not_measured[1])
            self.assertIn("MANDATORY_VERIFIER_DISABLED", not_measured[1])
            self.assertEqual(125, row["exit_code"])


if __name__ == "__main__":
    unittest.main()
