import json
import pathlib
import tempfile
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.oci_artifact import GenerateOciArtifactCommand
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom


@pytest.mark.asyncio
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_type", "expected_result_file"],
    [
        pytest.param(
            "spdx",
            "oci_artifact_sbom.spdx.json",
            id="SPDX oci artifact",
        ),
        pytest.param(
            "cyclonedx",
            "oci_artifact_sbom.cyclonedx.json",
            id="Cyclonedx oci artifact",
        ),
    ],
)
async def test_GenerateOciArtifactCommand_execute(
    sbom_type: str, expected_result_file: str
) -> None:
    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.oci_copy_yaml = current_dir.parent.parent / "data/oci_copy_example.yaml"
    args.image_pullspec = "quay.io/example/base:v9.0"
    args.image_digest = (
        "sha256:087dc7896b97911a582702b45ff1d41ffa3e142d0b000b0fbb11058188293cfc"
    )
    args.sbom_type = sbom_type

    expected_output_path = current_dir.parent.parent / "data" / expected_result_file
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateOciArtifactCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "oci_artifact.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            if sbom_type == "spdx":
                assert_spdx_sbom(result, expected_output)
            if sbom_type == "cyclonedx":
                assert_cdx_sbom(result, expected_output)


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_from_sbom_disk_image() -> None:
    """A disk image pushed as OCI artifact, with an osbuild content SBOM merged."""
    data = pathlib.Path(__file__).parent.parent.parent / "data" / "osbuild"
    args = MagicMock()
    args.oci_copy_yaml = data / "qcow2-oci-copy.yaml"
    args.image_pullspec = "quay.io/example/fedora-qcow2:44"
    args.image_digest = "sha256:" + "b" * 64
    args.sbom_type = "spdx"
    args.from_sbom = [data / "fedora-qcow2.image-os.spdx.json"]
    args.artifact_purpose = "FILE"

    command = GenerateOciArtifactCommand(args)
    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "out.json"
        await command.execute()
        await command.save()
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

    pkgs = {p["SPDXID"]: p for p in result["packages"]}
    disk = next(p for p in pkgs.values() if p["name"] == "disk.qcow2")
    assert disk["primaryPackagePurpose"] == "FILE"
    assert disk["versionInfo"] == "44"  # inherited from the OS root
    assert pkgs["SPDXRef-image-root"]["primaryPackagePurpose"] == "OPERATING_SYSTEM"
    rels = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in result["relationships"]
    }
    assert (disk["SPDXID"], "CONTAINS", "SPDXRef-image-root") in rels
    describes = [r for r in rels if r[1] == "DESCRIBES"]
    assert len(describes) == 1 and describes[0][0] == "SPDXRef-DOCUMENT"
    assert "Tool: osbuild-194" in result["creationInfo"]["creators"]
    root_contains = [r for r in rels if r[:2] == ("SPDXRef-image-root", "CONTAINS")]
    assert len(root_contains) == 3


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_from_sbom_cdx_unsupported() -> None:
    args = MagicMock()
    args.oci_copy_yaml = (
        pathlib.Path(__file__).parent.parent.parent / "data/osbuild/qcow2-oci-copy.yaml"
    )
    args.image_pullspec = "quay.io/example/fedora-qcow2:44"
    args.image_digest = "sha256:" + "b" * 64
    args.sbom_type = "cyclonedx"
    args.from_sbom = [pathlib.Path("x.json")]
    with pytest.raises(ValueError):
        await GenerateOciArtifactCommand(args).execute()
