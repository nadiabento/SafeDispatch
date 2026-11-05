#!/usr/bin/env bash
# Compila e corre os testes
set -e
cd "$(dirname "$0")/.."
./scripts/build.sh
java -cp out mensageiro.TestRunner