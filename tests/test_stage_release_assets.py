import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/stage-release-assets.sh"


class StageReleaseAssetsTests(unittest.TestCase):
    def test_stages_only_supported_release_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            dist = root / "dist"
            dist.mkdir()
            for filename in ("dhcpv4-served.tar.gz", "dhcpv4-served.deb", "checksums.txt", "artifacts.json"):
                (dist / filename).write_text(filename)
            for arch in ("amd64",):
                binary = dist / f"dhcpv4-served_linux_{arch}_v1" / "dhcpv4-served"
                binary.parent.mkdir()
                binary.write_text(arch)
            utility = dist / "dhcpv4-srvctl_linux_amd64_v1" / "dhcpv4-srvctl"
            utility.parent.mkdir()
            utility.write_text("srvctl")
            output = root / "release-assets"
            subprocess.run([str(SCRIPT), str(dist), str(output)], check=True)
            self.assertEqual({p.name for p in output.iterdir()}, {
                "dhcpv4-served.tar.gz", "dhcpv4-served.deb", "checksums.txt",
                "dhcpv4-served-linux-amd64", "dhcpv4-srvctl-linux-amd64",
            })
            self.assertEqual((output / "dhcpv4-served-linux-amd64").read_text(), "amd64")

    def test_missing_required_output_fails_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            dist = root / "dist"
            dist.mkdir()
            result = subprocess.run([str(SCRIPT), str(dist), str(root / "out")], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
