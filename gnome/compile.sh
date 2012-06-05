#!/bin/sh

gcc -o himitsu himitsu.c $(pkg-config --cflags --libs openssl glib-2.0 gnome-keyring-1 gtk+-3.0)
