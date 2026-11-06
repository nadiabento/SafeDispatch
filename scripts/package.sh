#!/usr/bin/env bash
# Cria o zip de entrega. Uso: ./scripts/package.sh entrega-1
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:?indica o nome: entrega-1 | entrega-2 | final}"
mkdir -p dist
git archive --format=zip --prefix=mensageiro-seguro/ -o "dist/$N.zip" HEAD
echo "dist/$N.zip criado"