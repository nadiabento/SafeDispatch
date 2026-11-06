#!/usr/bin/env bash
# Compila e corre todos os testes.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/build.sh

# O separador do classpath é ':' em Linux/Mac e ';' em Windows (Git Bash)
SEP=":"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) SEP=";";; esac

java -cp "out/main${SEP}out/test" mensageiro.TestRunner