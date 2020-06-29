#!/usr/bin/bash

cat /proc/cpuinfo | grep "cpu cores" | wc -l
