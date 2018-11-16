#!/bin/bash -e
# Copyright 2018 Shift Devices AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        docker exec -it $container_name bash
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

    # Call a second time to enter the container.
    dockerdev
}

dockerdev
