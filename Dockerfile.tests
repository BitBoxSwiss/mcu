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
#
# Run with Docker:
# docker build --tag shift/mcu-base-tests -f Dockerfile.tests .
#

FROM shift/mcu-base
ENV DEBIAN_FRONTEND noninteractive
WORKDIR /app
COPY . /app

RUN gcc -v
RUN clang -v
ENV CC gcc
RUN cd /app/ && rm -rf docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=test -DCONTINUOUS_INTEGRATION=1 && make && make test
RUN cd /app/docker-build/ && valgrind --leak-check=full --num-callers=40 --suppressions=../.valgrind.supp --error-exitcode=1 bin/tests_api;
RUN cd /app/docker-build/ && valgrind --leak-check=full --num-callers=40 --error-exitcode=1 bin/tests_u2f_hid;
RUN cd /app/docker-build/ && valgrind --leak-check=full --num-callers=40 --error-exitcode=1 bin/tests_u2f_standard;
RUN cd /app/docker-build/ && valgrind --leak-check=full --num-callers=40 --error-exitcode=1 bin/tests_unit;
RUN cd /app && rm -rf /app/docker-build

RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=test -DCONTINUOUS_INTEGRATION=1 -DUSE_SECP256K1_LIB=ON && make && make test
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=test -DUSE_SECP256K1_LIB=OFF && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=bootloader -DUSE_SECP256K1_LIB=OFF && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=firmware -DUSE_SECP256K1_LIB=ON && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=firmware && make
RUN rm -rf /app/docker-build
ENV CC clang
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=test -DUSE_SECP256K1_LIB=ON && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=test -DUSE_SECP256K1_LIB=OFF && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=bootloader -DUSE_SECP256K1_LIB=OFF && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=firmware -DUSE_SECP256K1_LIB=ON && make
RUN rm -rf /app/docker-build
RUN cd /app/ && mkdir docker-build && cd docker-build && cmake .. -DBUILD_TYPE=firmware && make
RUN sha256sum docker-build/bin/*
