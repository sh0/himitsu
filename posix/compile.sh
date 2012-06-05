#!/bin/sh

gcc -o himitsu himitsu.c $(pkg-config --cflags --libs openssl)
