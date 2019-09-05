#!/bin/bash -e
#
# The MIT License (MIT)
#
# Copyright 2019 Shift Cryptosecurity AG
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
# OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

dockerdev () {
    local container_image=shift/mcu-base
    local container_name=mcu-dev

    if ! docker images | grep -q $container_image; then
        echo "No $container_image docker image found! Maybe you need to run 'docker build --tag $container_image -f Dockerfile.dev .'?" >&2
        exit 1
    fi

    # If already running, enter the container.
    if docker ps | grep -q $container_name; then
        docker exec --user=dockeruser --workdir=/app -it $container_name bash
        return
    fi

    if docker ps -a | grep -q $container_name; then
        docker rm $container_name
    fi

    local repo_path="$DIR"
    docker run \
           --detach \
           --privileged -v /dev/bus/usb:/dev/bus/usb \
           --interactive --tty \
           --name=$container_name \
           -v $repo_path:/app \
           $container_image bash

    # Use same user/group id as on the host, so that files are not created as root in the mounted
    # volume.
    docker exec -it $container_name groupadd -g `id -g` dockergroup
    docker exec -it $container_name useradd -u `id -u` -m -g dockergroup dockeruser

    # Call a second time to enter the container.
    dockerdev
}

dockerdev
