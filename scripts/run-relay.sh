#!/usr/bin/env bash
# Arranca o relay. Uso: ./scripts/run-relay.sh <porta>
cd "$(dirname "$0")/.."
java -cp out/main mensageiro.relay.RelayMain "$@"