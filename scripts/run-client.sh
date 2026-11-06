#!/usr/bin/env bash
# Arranca o cliente. Uso: ./scripts/run-client.sh <host> <porta>
cd "$(dirname "$0")/.."
java -cp out/main mensageiro.client.ClientMain "$@"