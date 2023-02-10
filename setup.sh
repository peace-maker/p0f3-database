#!/bin/bash

pip install -r requirements.txt
wget https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz
tar xfz p0f-3.09b.tgz
cd p0f-3.09b
./build.sh
