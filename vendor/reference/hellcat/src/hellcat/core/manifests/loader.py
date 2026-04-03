"""
Manifest Loader - Load and save manifests from files.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from hellcat.core.manifests.schema import ToolchainManifest


def load_manifest(path: Path | str) -> ToolchainManifest:
    """
    Load a manifest from a file.

    Supports YAML and JSON formats based on file extension.

    Args:
        path: Path to manifest file (.yaml, .yml, or .json)

    Returns:
        Loaded ToolchainManifest

    Raises:
        ValueError: If file format is not supported
        FileNotFoundError: If file doesn't exist
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {path}")

    content = path.read_text()

    if path.suffix in (".yaml", ".yml"):
        data = yaml.safe_load(content)
    elif path.suffix == ".json":
        data = json.loads(content)
    else:
        raise ValueError(f"Unsupported manifest format: {path.suffix}")

    return ToolchainManifest.from_dict(data)


def save_manifest(manifest: ToolchainManifest, path: Path | str) -> None:
    """
    Save a manifest to a file.

    Supports YAML and JSON formats based on file extension.

    Args:
        manifest: Manifest to save
        path: Destination path (.yaml, .yml, or .json)

    Raises:
        ValueError: If file format is not supported
    """
    path = Path(path)
    data = manifest.to_dict()

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix in (".yaml", ".yml"):
        content = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    elif path.suffix == ".json":
        content = json.dumps(data, indent=2)
    else:
        raise ValueError(f"Unsupported manifest format: {path.suffix}")

    path.write_text(content)


def load_manifest_from_string(content: str, format: str = "yaml") -> ToolchainManifest:
    """
    Load a manifest from a string.

    Args:
        content: Manifest content as string
        format: Format of content ("yaml" or "json")

    Returns:
        Loaded ToolchainManifest
    """
    if format == "yaml":
        data = yaml.safe_load(content)
    elif format == "json":
        data = json.loads(content)
    else:
        raise ValueError(f"Unsupported format: {format}")

    return ToolchainManifest.from_dict(data)


def manifest_to_string(manifest: ToolchainManifest, format: str = "yaml") -> str:
    """
    Convert a manifest to a string.

    Args:
        manifest: Manifest to convert
        format: Output format ("yaml" or "json")

    Returns:
        Manifest as string
    """
    data = manifest.to_dict()

    if format == "yaml":
        return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    elif format == "json":
        return json.dumps(data, indent=2)
    else:
        raise ValueError(f"Unsupported format: {format}")
