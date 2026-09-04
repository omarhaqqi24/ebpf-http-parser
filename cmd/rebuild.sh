#!/bin/bash

cd xdp && go generate 
cd ../socket && go generate
cd .. && go build -o bpf