"""Per-client OCI label remap extension (optional; not loaded by default)."""

from .grype_oci_tags import (
    HRDB_PREFIX,
    NEW_AUTHORS_LABEL,
    WORKSPACE_PREFIX,
    apply_oci_label_remap_to_grype_translator,
    build_label_value_transforms,
    get_new_authors_key_prefix,
    transform_new_authors_key_value,
)

__all__ = [
    "HRDB_PREFIX",
    "NEW_AUTHORS_LABEL",
    "WORKSPACE_PREFIX",
    "apply_oci_label_remap_to_grype_translator",
    "build_label_value_transforms",
    "get_new_authors_key_prefix",
    "transform_new_authors_key_value",
]
