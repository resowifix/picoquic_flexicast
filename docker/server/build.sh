#!/bin/sh

sudo docker build --build-arg BUILD_ARG=$(date +%s) -t resowifix/picoquic-fc-dtgrm-server .; sudo docker push resowifix/picoquic-fc-dtgrm-server:latest
