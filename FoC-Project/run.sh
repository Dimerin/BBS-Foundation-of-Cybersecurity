#!/bin/bash

# Compile the server and client
make clean
make
if [ $? -ne 0 ]; then
    echo "Failed to compile the server and client. Exiting..."
    exit 1
fi


# Run the server and client in separate terminals
gnome-terminal -- bash -c "./bin/server; exec bash"
gnome-terminal -- bash -c "./bin/client; exec bash"