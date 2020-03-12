#!/bin/sh

exec cargo tarpaulin \
    --ignore-tests   \
    --out Xml        \
    --verbose
