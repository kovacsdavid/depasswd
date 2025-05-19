#!/bin/bash

cargo test && cargo audit && cargo build -r
