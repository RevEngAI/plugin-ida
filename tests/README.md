# Tests

Two tiers, one pytest run:

- `tests/unit/` — fast tests with all external services (RevEng.AI API, etc.)
  mocked. No binary or IDA needed.
- `tests/idalib/` — tests that open a real binary under headless IDA (idalib)
  to exercise plugin code end-to-end. Marked `@pytest.mark.idalib`.

## How the harness resolves dependencies

The shipped plugin runs off its bundled `reai_toolkit/vendor/` (see
`reai_toolkit_entry._add_vendor_paths`), **not** site-packages. The tests do the
same so they exercise the exact dependency set that ships. `tests/conftest.py`:

1. Derives `IDADIR` from `~/.idapro/ida-config.json` (or honours an existing
   `IDADIR`).
2. Points `IDAUSR` at a hermetic temp dir so IDA's plugin scanner does not
   inject other plugins' stale `vendor/` dirs onto `sys.path`.
3. Leaves that `IDAUSR` empty — licensing is provided by the runner
   image/environment, not seeded here.
4. `import idapro` (boots the headless kernel).
5. Prepends `reai_toolkit/vendor/` and the repo root to `sys.path`.

`reai_toolkit/vendor/` is git-ignored build output. Regenerate it from the
current `pyproject.toml` before running tests (this is the same step
`publish.yaml` runs):

```bash
uv sync
mkdir -p reai_toolkit/vendor
uv pip install . --target reai_toolkit/vendor --no-cache-dir
rm -rf reai_toolkit/vendor/reai_toolkit reai_toolkit/vendor/reai_toolkit-*.dist-info
```

## One-time idalib activation (local)

idalib must be activated against your installed IDA Pro once. On macOS:

```bash
python "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

This writes `~/.idapro/ida-config.json`, which conftest reads for `IDADIR`.

## Running

```bash
uv run pytest                  # full suite
uv run pytest -m "not idalib"  # unit tests only
uv run pytest -m idalib        # idalib tests only
```

## Rebuilding the ELF fixture

`tests/fixtures/hello.elf` is a tiny x86_64 Linux ELF (dynamic, unstripped so
IDA names functions). Rebuild with Docker:

```bash
docker run --rm --platform linux/amd64 -v "$PWD/tests/fixtures":/out gcc:14 sh -c '
  cat > /tmp/hello.c <<EOF
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) { printf("hello %d\n", add(2, 3)); return 0; }
EOF
  gcc -O0 -fno-omit-frame-pointer -o /out/hello.elf /tmp/hello.c && chmod 644 /out/hello.elf'
```

