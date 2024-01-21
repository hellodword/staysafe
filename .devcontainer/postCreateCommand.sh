#! /bin/bash

set -e
set -x

# install dep
sudo apt-get update
sudo apt-get install -y \
  vim \
  bash-completion
