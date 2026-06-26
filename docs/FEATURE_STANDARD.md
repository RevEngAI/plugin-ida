# Feature manifest

This repo publishes `.revengai/features.json`, a machine-readable manifest listing which
RevEng.AI features this plugin supports. It is generated from code and committed so it is
available at every release tag.

## Source of truth

Feature support is declared in [`scripts/emit_features.py`](../scripts/emit_features.py):

- `ACTIONS` maps real plugin action ids (the `reai:*` menu actions and `revengai:*` popup
  actions registered in `reai_toolkit/hooks/`) to a `feature_id` + status.
- `EXTRA` declares features not tied to a single action id (uploads, hooks, the
  function-search filters, comment/data-type sync, etc.).
- `build_manifest()` merges the two.

`.revengai/features.json` is generated from this script — never edit the JSON by hand. The
script lives in `scripts/` (not in the `reai_toolkit` package) so it is build tooling and
is not shipped with the plugin.

## Status values

`yes`, `partial`, `poc`, `wip`, `planned`, `absent`. A feature may carry an optional `note`
(<=200 chars).

Feature ids are a shared vocabulary used consistently across the RevEng.AI plugins; reuse
an existing id, or coordinate with the team before introducing a new one.

## Regenerating

```sh
python scripts/emit_features.py          # rewrite .revengai/features.json
python scripts/emit_features.py --check  # exit non-zero if it is stale
```

Standard library only (no `ida_*` imports), so it runs in plain CI without IDA.

## CI

`.github/workflows/features-drift.yml` runs `--check` on every pull request and fails if
the committed `.revengai/features.json` does not match the script. When you add or change
a feature: update `scripts/emit_features.py`, run the emitter, and commit both.
