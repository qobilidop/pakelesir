# pakeles (Python)

The Python authoring eDSL for the Pakeles IR — see
`docs/superpowers/specs/2026-07-19-python-edsl-design.md` and the root
README. Authoring happens here; validation authority stays with the Rust
CLI (`pakeles lint`).

Dev loop (from the repo root, inside the dev container):

```sh
./dev.sh sh -c 'cd py && ruff check . && pyright && pytest'
```

Regenerate the vendored proto modules after editing `proto/`:

```sh
./dev.sh sh -c 'protoc --proto_path=proto --python_out=/tmp/pbgen --pyi_out=/tmp/pbgen \
    proto/pakeles/ir/v1alpha1/ir.proto proto/pakeles/testvec/v1alpha1/testvec.proto \
  && cp /tmp/pbgen/pakeles/ir/v1alpha1/ir_pb2.py* py/src/pakeles/_pb/ \
  && cp /tmp/pbgen/pakeles/testvec/v1alpha1/testvec_pb2.py* py/src/pakeles/_pb/'
```
