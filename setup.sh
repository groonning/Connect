#!/usr/bin/env bash
# Thin wrapper — the real installer lives in `connect install`.
cd "$(dirname "$(readlink -f "$0")")"
exec sudo bash connect install "$@"
