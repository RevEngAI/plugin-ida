#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR="reai_toolkit/vendor"
REQ="$(mktemp -t reai-vendor-req.XXXXXX)"
trap 'rm -f "$REQ"' EXIT

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is not on PATH; see https://docs.astral.sh/uv/getting-started/install/" >&2
    exit 1
fi

echo "==> Exporting locked runtime dependencies from uv.lock"
uv export --frozen --no-dev --no-emit-project --no-hashes -o "$REQ" >/dev/null

echo "==> Rebuilding vendor tree at $VENDOR"
rm -rf "$VENDOR"
mkdir -p "$VENDOR"
uv pip install -r "$REQ" --target "$VENDOR" --no-cache-dir

echo "==> Dropping the self-install so the checkout is not shadowed"
rm -rf "$VENDOR/reai_toolkit" "$VENDOR"/reai_toolkit-*.dist-info

echo "==> Verifying the vendor tree matches uv.lock"
uv run python scripts/check_vendor.py

echo "==> Vendored (this is what the plugin and the tests import)"
for dist in "$VENDOR"/*.dist-info; do
    [ -d "$dist" ] || continue
    name="$(basename "$dist" .dist-info)"
    case "$name" in
        revengai-* | libbs-* | pydantic-* | loguru-* | requests-*)
            echo "    ${name%-*} ${name##*-}"
            ;;
    esac
done

echo "==> $VENDOR is prepended to sys.path ahead of site-packages,"
echo "    so rerun this after any dependency change or the old tree wins."
