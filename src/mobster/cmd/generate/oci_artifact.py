"""A module for generating SBOM documents for OCI artifact images."""

import json
import logging
from pathlib import Path
from typing import Any

import yaml
from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package, PackagePurpose
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import (
    JsonLikeDictParser,
)

from mobster.artifact import Artifact
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx

LOGGER = logging.getLogger(__name__)


class GenerateOciArtifactCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for an OCI artifact.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for oci artifact.
        """
        with open(self.cli_args.oci_copy_yaml, encoding="utf-8") as oci_copy_file:
            oci_copy_data = yaml.safe_load(oci_copy_file)

        artifacts = [Artifact(**artifact) for artifact in oci_copy_data["artifacts"]]
        oci_image = Image.from_image_index_url_and_digest(
            self.cli_args.image_pullspec,
            self.cli_args.image_digest,
        )

        sbom = self.to_sbom(oci_image, artifacts)

        self._content = sbom
        return self.content

    @property
    def content_sboms(self) -> list[Path]:
        """Content SBOMs (e.g. osbuild/image-builder) describing the artifact."""
        value = getattr(self.cli_args, "from_sbom", None)
        return list(value) if isinstance(value, list) else []

    @property
    def artifact_purpose(self) -> PackagePurpose | None:
        """Optional SPDX primaryPackagePurpose for the artifact packages."""
        value = getattr(self.cli_args, "artifact_purpose", None)
        if not isinstance(value, str):
            return None
        return PackagePurpose[value.upper().replace("-", "_")]

    def to_sbom(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate an SBOM document for oci artifact.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in the specified format (CycloneDX or SPDX)
            based on the command line arguments.
        """
        if self.cli_args.sbom_type == "cyclonedx":
            if self.content_sboms:
                raise ValueError("--from-sbom is only supported with --sbom-type spdx")
            return self.to_cyclonedx(oci_image, artifacts)
        return self.to_spdx(oci_image, artifacts)

    def to_cyclonedx(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate a CycloneDX SBOM document for oci artifact image.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in cyclonedx format.
        """

        root_component = cyclonedx.get_component(oci_image)

        # Create CycloneDX BOM and assign it the root component
        document = Bom()
        document.metadata.tools.components.add(cyclonedx.get_tools_component())
        document.metadata.component = root_component
        document.metadata.manufacturer = cyclonedx.get_manufacturer()

        artifact_components = [
            cyclonedx.get_component_from_artifact(artifact) for artifact in artifacts
        ]

        for artifact_component in artifact_components:
            document.components.add(artifact_component)

        document.components.add(root_component)

        # Add the dependencies between the root component and artifact components
        document.dependencies.add(
            Dependency(
                ref=root_component.bom_ref,
                dependencies=[
                    Dependency(artifact.bom_ref) for artifact in artifact_components
                ],
            )
        )
        return document

    def to_spdx(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate a SPDX SBOM document for oci artifact image.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in SPDX format.
        """
        packages = [spdx.get_image_package(oci_image, oci_image.propose_spdx_id())]
        artifact_packages = [
            spdx.get_package_from_artifact(artifact) for artifact in artifacts
        ]
        packages.extend(artifact_packages)
        relationships = [
            spdx.get_root_package_relationship(oci_image.propose_spdx_id()),
        ]
        for artifact in artifacts:
            relationships.append(
                self.get_artifact_relationship(
                    artifact.propose_spdx_id(), oci_image.propose_spdx_id()
                )
            )
        document = Document(
            creation_info=spdx.get_creation_info(oci_image.propose_sbom_name()),
            packages=packages,
            relationships=relationships,
        )

        for package in artifact_packages:
            if self.artifact_purpose is not None:
                package.primary_package_purpose = self.artifact_purpose

        if self.content_sboms:
            if len(artifact_packages) != 1:
                raise ValueError(
                    "--from-sbom requires exactly one artifact in the oci-copy YAML"
                )
            for content_sbom in self.content_sboms:
                self.merge_content_sbom(
                    document,
                    artifact_packages[0],
                    content_sbom,
                    fold_root=bool(getattr(self.cli_args, "fold_content_root", False)),
                )

        return document

    @staticmethod
    def merge_content_sbom(
        document: Document,
        artifact_package: Package,
        content_sbom_path: Path,
        fold_root: bool = False,
    ) -> None:
        """
        Merge an SPDX content SBOM (e.g. from osbuild/image-builder describing
        the content of a disk image) into the document under the artifact.

        Every element DESCRIBED by the content SBOM becomes CONTAINED by the
        artifact package. If the artifact package has no version, it inherits
        the version of the single described content root (if any).

        With fold_root, a single described content root (e.g. osbuild's logical
        OPERATING_SYSTEM package, which has no checksum because the disk digest
        is unknown at manifest time) is folded into the artifact package: its
        purl is added to the artifact, its relationships are re-pointed to the
        artifact, and the root package itself is dropped.
        """
        with open(content_sbom_path, encoding="utf-8") as sbom_file:
            content = JsonLikeDictParser().parse(  # type: ignore[no-untyped-call]
                json.load(sbom_file)
            )
        existing_ids = {pkg.spdx_id for pkg in document.packages}
        content_doc_id = content.creation_info.spdx_id
        described = [
            r.related_spdx_element_id
            for r in content.relationships
            if r.relationship_type == RelationshipType.DESCRIBES
            and r.spdx_element_id == content_doc_id
        ]
        folded: str | None = None
        if fold_root and len(described) == 1 and isinstance(described[0], str):
            folded = described[0]
            root_pkg = next(p for p in content.packages if p.spdx_id == folded)
            for ref in root_pkg.external_references:
                if ref not in artifact_package.external_references:
                    artifact_package.external_references.append(ref)
            if not artifact_package.version:
                artifact_package.version = root_pkg.version
            if artifact_package.primary_package_purpose is None:
                artifact_package.primary_package_purpose = (
                    root_pkg.primary_package_purpose
                )
            content.packages = [p for p in content.packages if p.spdx_id != folded]
            content.relationships = [
                r
                for r in content.relationships
                if not (
                    r.relationship_type == RelationshipType.DESCRIBES
                    and r.related_spdx_element_id == folded
                )
            ]
            for r in content.relationships:
                if r.spdx_element_id == folded:
                    r.spdx_element_id = artifact_package.spdx_id
                if r.related_spdx_element_id == folded:
                    r.related_spdx_element_id = artifact_package.spdx_id
        roots = []
        for package in content.packages:
            if package.spdx_id not in existing_ids:
                document.packages.append(package)
                existing_ids.add(package.spdx_id)
        for rel in content.relationships:
            if (
                rel.relationship_type == RelationshipType.DESCRIBES
                and rel.spdx_element_id == content_doc_id
            ):
                roots.append(rel.related_spdx_element_id)
                document.relationships.append(
                    Relationship(
                        spdx_element_id=artifact_package.spdx_id,
                        relationship_type=RelationshipType.CONTAINS,
                        related_spdx_element_id=rel.related_spdx_element_id,
                    )
                )
            else:
                document.relationships.append(rel)
        known_lics = {lic.license_id for lic in document.extracted_licensing_info}
        for lic in content.extracted_licensing_info:
            if lic.license_id not in known_lics:
                document.extracted_licensing_info.append(lic)
        for creator in content.creation_info.creators:
            if creator not in document.creation_info.creators:
                document.creation_info.creators.append(creator)
        if not artifact_package.version and len(roots) == 1:
            root = next(p for p in document.packages if p.spdx_id == roots[0])
            artifact_package.version = root.version

    def get_artifact_relationship(
        self, spdx_id: str, oci_image_spdx_id: str
    ) -> Relationship:
        """
        Get a relationship for the artifact in relation to the main image.
        This relationship indicates artifact is contained within the OCI image.

        Args:
            spdx_id (str): An SPDX ID for the artifact.
            oci_image_spdx_id: str: An SPDX ID for the main image.

        Returns:
            Relationship: A SPDX relationship object for the child image.
        """
        return Relationship(
            spdx_element_id=oci_image_spdx_id,
            relationship_type=RelationshipType.CONTAINS,
            related_spdx_element_id=spdx_id,
        )
