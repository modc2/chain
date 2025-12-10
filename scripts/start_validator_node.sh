#!/usr/bin/env bash
set -e

NODE_PATH="$(pwd)/target/release/modnet-node"
$NODE_PATH \
  --chain modnet-testnet-raw.json \
  --validator \
  --name BootNode-01 \
  --node-key 40ffa204f07664248b1d10d5a57a28877206fb82ac356f9273824dae81375e81 \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --rpc-cors all \
  --rpc-port 9933 \
  --rpc-methods Safe \
  --force-authoring \
  --base-path ~/.modnet/data