#!/bin/bash

go generate && go build

sudo ./xdp-sniffer