import argparse
import json
import sys
from pathlib import Path

PLUGIN = "ida"

ACTIONS = {
    "reai:analyse": ("analyse_binary", "yes"),
    "reai:existing_analysis": ("apply_existing_analysis", "yes"),
    "reai:sync_and_poll": ("check_analysis_status", "yes"),
    "reai:function_match": ("rename_from_similar_function", "yes"),
    "revengai:toggle_ai_decomp": ("function_decompilation", "yes"),
}

EXTRA = {
    "binary_upload": {"status": "yes"},
    "disable_private_analyses": {"status": "yes"},
    "view_analysis_logs": {"status": "yes"},
    "fs_collection_filter": {"status": "yes"},
    "fs_binary_filter": {"status": "yes"},
    "fs_debug_filter": {"status": "yes"},
    "fs_nns_filter": {"status": "partial"},
    "fs_similarity_filter": {"status": "yes"},
    "upload_function_names": {"status": "yes"},
    "hook_function_rename": {"status": "yes"},
    "upload_data_types": {
        "status": "partial",
        "note": (
            "Hooks variable rename and type changes and pushes them to RevEng.AI. "
            "Register-allocated local variables are not synced: libbs/declib does not "
            "extract register vars and the RevEng data-types schema has no register-variable "
            "field (only function arguments and stack variables). Function arguments, stack "
            "variables, return type, and referenced type definitions are synced."
        ),
    },
    "upload_variable_rename_or_type_change": {"status": "yes"},
    "data_types_sync": {"status": "yes"},
    "comment_sync": {"status": "partial"},
    "search": {"status": "yes"},
    "ai_decompilation_summary": {"status": "yes"},
}

MANIFEST_PATH = Path(__file__).resolve().parent.parent / ".revengai" / "features.json"


def build_manifest():
    features = {}
    for _action_id, (feature_id, status) in ACTIONS.items():
        features.setdefault(feature_id, {"status": status})
    for feature_id, entry in EXTRA.items():
        features.setdefault(feature_id, dict(entry))
    return {"schema_version": 1, "plugin": PLUGIN, "features": features}


def serialize():
    return json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    content = serialize()
    if args.check:
        current = MANIFEST_PATH.read_text() if MANIFEST_PATH.exists() else ""
        if current != content:
            print(
                "features.json is out of date; run: python scripts/emit_features.py",
                file=sys.stderr,
            )
            return 1
        print("features.json is up to date.")
        return 0

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(content)
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
