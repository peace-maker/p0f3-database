#!/bin/sh

basedir=$(dirname $0)

python "$basedir/p0f.py" --p0f-path "$basedir/p0f-3.09b/p0f" --p0f-database-path "$basedir/p0f.fp" $@
