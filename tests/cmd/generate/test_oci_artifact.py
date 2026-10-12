import json
import pathlib
import tempfile
from typing import Any
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
    args.fold_content_root = False

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
async def test_GenerateOciArtifactCommand_from_sbom_fold_root() -> None:
    """--fold-content-root merges the checksum-less OS root into the artifact."""
    data = pathlib.Path(__file__).parent.parent.parent / "data" / "osbuild"
    args = MagicMock()
    args.oci_copy_yaml = data / "qcow2-oci-copy.yaml"
    args.image_pullspec = "quay.io/example/fedora-qcow2:44"
    args.image_digest = "sha256:" + "b" * 64
    args.sbom_type = "spdx"
    args.from_sbom = [data / "fedora-qcow2.image-os.spdx.json"]
    args.artifact_purpose = None
    args.fold_content_root = True

    command = GenerateOciArtifactCommand(args)
    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "out.json"
        await command.execute()
        await command.save()
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

    pkgs = {p["SPDXID"]: p for p in result["packages"]}
    assert "SPDXRef-image-root" not in pkgs
    disk = next(p for p in pkgs.values() if p["name"] == "disk.qcow2")
    assert disk["primaryPackagePurpose"] == "OPERATING_SYSTEM"
    assert disk["versionInfo"] == "44"
    assert any(
        r["referenceLocator"].startswith("pkg:generic/") for r in disk["externalRefs"]
    )
    rels = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in result["relationships"]
    }
    assert not any("SPDXRef-image-root" in (r[0], r[2]) for r in rels)
    assert len([r for r in rels if r[:2] == (disk["SPDXID"], "CONTAINS")]) == 3


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


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_from_sbom_keeps_external_refs() -> None:
    """externalDocumentRefs of the content SBOM (linked build root) are kept."""
    data = pathlib.Path(__file__).parent.parent.parent / "data" / "osbuild"
    content = json.loads((data / "fedora-qcow2.image-os.spdx.json").read_text())
    content["externalDocumentRefs"] = [
        {
            "externalDocumentId": "DocumentRef-buildroot-build",
            "spdxDocument": "https://example.com/buildroot",
            "checksum": {"algorithm": "SHA1", "checksumValue": "a" * 40},
        }
    ]
    content["creationInfo"]["comment"] = "SBOM generation context: build."
    content["relationships"].append(
        {
            "spdxElementId": "DocumentRef-buildroot-build:SPDXRef-DOCUMENT",
            "relationshipType": "BUILD_TOOL_OF",
            "relatedSpdxElement": "SPDXRef-image-root",
        }
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        content_path = pathlib.Path(temp_dir) / "content.spdx.json"
        content_path.write_text(json.dumps(content))
        args = MagicMock()
        args.oci_copy_yaml = data / "qcow2-oci-copy.yaml"
        args.image_pullspec = "quay.io/example/fedora-qcow2:44"
        args.image_digest = "sha256:" + "b" * 64
        args.sbom_type = "spdx"
        args.from_sbom = [content_path]
        args.artifact_purpose = None
        args.fold_content_root = True
        command = GenerateOciArtifactCommand(args)
        args.output = pathlib.Path(temp_dir) / "out.json"
        await command.execute()
        await command.save()
        result = json.loads(args.output.read_text())

    assert result["creationInfo"]["comment"] == "SBOM generation context: build."
    assert [r["externalDocumentId"] for r in result["externalDocumentRefs"]] == [
        "DocumentRef-buildroot-build"
    ]
    disk = next(p for p in result["packages"] if p["name"] == "disk.qcow2")
    assert {
        "spdxElementId": "DocumentRef-buildroot-build:SPDXRef-DOCUMENT",
        "relationshipType": "BUILD_TOOL_OF",
        "relatedSpdxElement": disk["SPDXID"],
    } in result["relationships"]


async def _fold(content: dict[str, Any]) -> dict[str, Any]:
    data = pathlib.Path(__file__).parent.parent.parent / "data" / "osbuild"
    with tempfile.TemporaryDirectory() as temp_dir:
        content_path = pathlib.Path(temp_dir) / "content.spdx.json"
        content_path.write_text(json.dumps(content))
        args = MagicMock()
        args.oci_copy_yaml = data / "qcow2-oci-copy.yaml"
        args.image_pullspec = "quay.io/example/fedora-qcow2:44"
        args.image_digest = "sha256:" + "b" * 64
        args.sbom_type = "spdx"
        args.from_sbom = [content_path]
        args.artifact_purpose = None
        args.fold_content_root = True
        command = GenerateOciArtifactCommand(args)
        args.output = pathlib.Path(temp_dir) / "out.json"
        await command.execute()
        await command.save()
        return json.loads(args.output.read_text())  # type: ignore[no-any-return]


def _osbuild_content() -> dict[str, Any]:
    data = pathlib.Path(__file__).parent.parent.parent / "data" / "osbuild"
    return json.loads(  # type: ignore[no-any-return]
        (data / "fedora-qcow2.image-os.spdx.json").read_text()
    )


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_from_sbom_keeps_annotations() -> None:
    """Package annotations of the content SBOM (e.g. download_url) are kept."""
    content = _osbuild_content()
    pkg = next(p for p in content["packages"] if p["SPDXID"] != "SPDXRef-image-root")
    pkg["annotations"] = [
        {
            "annotationType": "OTHER",
            "annotator": "Tool: osbuild-194",
            "annotationDate": "2026-10-13T00:00:00Z",
            "comment": "download_url: https://mirror.example/x.rpm",
        }
    ]
    result = await _fold(content)
    out = next(p for p in result["packages"] if p["SPDXID"] == pkg["SPDXID"])
    assert (
        out["annotations"][0]["comment"] == "download_url: https://mirror.example/x.rpm"
    )


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_fold_root_checksum_matches() -> None:
    """A root SHA256 (image-builder build) equal to the pushed file is accepted."""
    content = _osbuild_content()
    root = next(p for p in content["packages"] if p["SPDXID"] == "SPDXRef-image-root")
    root["checksums"] = [{"algorithm": "SHA256", "checksumValue": "c" * 64}]
    result = await _fold(content)
    disk = next(p for p in result["packages"] if p["name"] == "disk.qcow2")
    assert disk["checksums"] == [{"algorithm": "SHA256", "checksumValue": "c" * 64}]


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_fold_root_checksum_mismatch() -> None:
    """A root SHA256 for a different file than the pushed artifact is an error."""
    content = _osbuild_content()
    root = next(p for p in content["packages"] if p["SPDXID"] == "SPDXRef-image-root")
    root["checksums"] = [{"algorithm": "SHA256", "checksumValue": "d" * 64}]
    with pytest.raises(ValueError, match="records SHA256"):
        await _fold(content)
