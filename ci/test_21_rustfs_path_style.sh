#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
set -Eeu

# Test RustFS with S3 path-style addressing.

export AWS_ACCESS_KEY_ID=ANTN35UAENTS5UIAEATD
export AWS_SECRET_ACCESS_KEY=TtnuieannGt2rGuie2t8Tt7urarg5nauedRndrur
export DOMAIN=s3.us-east-1.rusoto.example.com
S3_TEST_PORT=${S3_TEST_PORT:-9000}
export S3_ENDPOINT="http://$DOMAIN:$S3_TEST_PORT"
export S3_PROXY=http://127.0.0.1:$S3_TEST_PORT
export S3_ADDRESSING_STYLE=path

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT/integration_tests"
./docker_test_run.py \
    --docker-image="ghcr.io/rustfs/rustfs:1.0.4" \
    --port="$S3_TEST_PORT" \
    --health-path=/health/ready \
    --run-opt="-p=$S3_TEST_PORT:9000" \
    --run-opt=--env=RUSTFS_ACCESS_KEY=$AWS_ACCESS_KEY_ID \
    --run-opt=--env=RUSTFS_SECRET_KEY=$AWS_SECRET_ACCESS_KEY \
    --run-opt="--env=RUSTFS_SERVER_DOMAINS=$DOMAIN:$S3_TEST_PORT" \
    --run-opt=--env=RUSTFS_CONSOLE_ENABLE=false \
    --run-arg=/data \
    -- cargo test --test s3 --features s3,disable_s3_acl_tests ---- --test-threads 1
