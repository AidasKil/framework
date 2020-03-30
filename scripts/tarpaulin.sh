#!/bin/sh

exec cargo tarpaulin \
    --ignore-tests   \
    --out Xml        \
    --timeout 240    \
    --verbose
