#!/usr/bin/env bash
# Compila o código principal (out/main) e os testes (out/test).
set -euo pipefail
cd "$(dirname "$0")/.."          # vai para a raiz do repo, onde quer que seja chamado

rm -rf out && mkdir -p out/main out/test

# Compila todos os .java de src/main e depois os de src/test (que dependem do main)
javac -d out/main $(find src/main -name '*.java')
javac -cp out/main -d out/test $(find src/test -name '*.java')

echo "build ok"