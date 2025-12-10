#! /usr/bin/env bash
set -e

NODE_PATH="$(pwd)/target/release/modnet-node"
$NODE_PATH \
  --chain modnet-testnet-raw.json \
  --base-path ~/.modnet/data