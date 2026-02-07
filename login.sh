#!/bin/bash
printf "Username: "
read user
exec ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no "${user}@127.0.0.1"
