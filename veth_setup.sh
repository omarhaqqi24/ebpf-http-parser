#!/bin/bash

# 1. Create namespaces
sudo ip netns add client
sudo ip netns add server

# 2. Create veth pair
sudo ip link add veth-client type veth peer name veth-server

# 3. Move each end into its namespace
sudo ip link set veth-client netns client
sudo ip link set veth-server netns server

# 4. Configure client interface
sudo ip netns exec client ip addr add 192.168.0.1/24 dev veth-client
sudo ip netns exec client ip link set veth-client up
sudo ip netns exec client ip link set lo up

# 5. Configure server interface
sudo ip netns exec server ip addr add 192.168.0.2/24 dev veth-server
sudo ip netns exec server ip link set veth-server up
sudo ip netns exec server ip link set lo up

# 6. Set MTU
sudo ip netns exec client ip link set dev veth-client mtu 500
sudo ip netns exec server ip link set dev veth-server mtu 500