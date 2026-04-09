#!/usr/bin/env bash
# gen_proto.sh — compile proto/guardian.proto to Python gRPC stubs.
# Generated files land in proto/ and are .gitignored.
#
# Usage:
#   bash scripts/gen_proto.sh
#
# Requirements:
#   pip install grpcio-tools

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
PROTO_FILE="$PROTO_DIR/guardian.proto"

echo "Compiling $PROTO_FILE …"

python -m grpc_tools.protoc \
  --proto_path="$PROTO_DIR" \
  --python_out="$PROTO_DIR" \
  --grpc_python_out="$PROTO_DIR" \
  "$PROTO_FILE"

# Fix the import in the generated gRPC stub so it works as a package import.
# grpc_tools generates:  import guardian_pb2 as guardian__pb2
# We need:               from proto import guardian_pb2 as guardian__pb2
GRPC_STUB="$PROTO_DIR/guardian_pb2_grpc.py"
if [ -f "$GRPC_STUB" ]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' 's/^import guardian_pb2/from proto import guardian_pb2/' "$GRPC_STUB"
  else
    sed -i 's/^import guardian_pb2/from proto import guardian_pb2/' "$GRPC_STUB"
  fi
  echo "Fixed import in $GRPC_STUB"
fi

echo "Done. Generated:"
echo "  proto/guardian_pb2.py"
echo "  proto/guardian_pb2_grpc.py"
