import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "validate_release_sboms", Path(__file__).resolve().parents[1] / "scripts/validate_release_sboms.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ReleaseSBOMTests(unittest.TestCase):
    def test_binary_binding_and_embedded_module_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "binary"
            binary.write_bytes(b"binary")
            info = "binary: go1.26.0\n\tdep\texample.org/module\tv1.0.0\th1:abc\n"
            sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {
                "version": "sha256:" + validator.digest(binary)}}, "components": [
                    {"name": "stdlib", "version": "go1.26.0"},
                    {"name": "example.org/module", "version": "v1.0.0"},
                ]}
            self.assertEqual(validator.validate(binary, sbom, info), "go1.26.0")
            missing = copy.deepcopy(sbom)
            missing["components"].pop()
            with self.assertRaisesRegex(ValueError, "missing embedded module"):
                validator.validate(binary, missing, info)
            missing = copy.deepcopy(sbom)
            missing["components"].pop(0)
            with self.assertRaisesRegex(ValueError, "standard library"):
                validator.validate(binary, missing, info)
            binary.write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "digest"):
                validator.validate(binary, sbom, info)

    def test_unreviewed_replacement_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "binary"
            binary.write_bytes(b"binary")
            sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {
                "version": "sha256:" + validator.digest(binary)}}, "components": [
                    {"name": "stdlib", "version": "go1.26.0"},
                ]}
            with self.assertRaisesRegex(ValueError, "replacements"):
                validator.validate(binary, sbom, "binary: go1.26.0\n\t=>\tother\tv1.0.0\n")

    def test_reviewed_varlink_replacement_must_appear_in_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "binary"
            binary.write_bytes(b"binary")
            version = "v2.0.0-20260611234345-b30f18e21e83"
            info = (f"binary: go1.26.0\n\tdep\tgithub.com/varlink/go/v2\t{version}\n"
                    f"\t=>\tgithub.com/noxiouz/go/v2\t{version}\th1:abc\n")
            sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {
                "version": "sha256:" + validator.digest(binary)}}, "components": [
                    {"name": "stdlib", "version": "go1.26.0"},
                    {"name": "github.com/noxiouz/go/v2", "version": version},
                ]}
            self.assertEqual(validator.validate(binary, sbom, info), "go1.26.0")
            with self.assertRaisesRegex(ValueError, "replacements"):
                validator.validate(binary, sbom, info.replace(f"{version}\th1:abc", "v2.1.0\th1:abc"))
            sbom["components"].pop()
            with self.assertRaisesRegex(ValueError, "missing embedded module"):
                validator.validate(binary, sbom, info)


if __name__ == "__main__":
    unittest.main()
