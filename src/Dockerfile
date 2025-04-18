FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y pkg-config build-essential git cmake \
    zlib1g-dev libevent-dev \
    libelf-dev libwebsockets-dev libyaml-dev llvm \
    clang libc6-dev-i386 \
    libssl-dev libcurl4-openssl-dev uncrustify curl jq containerd

RUN mkdir /src && \
    git init
WORKDIR /src

# Link asm/byteorder.h into eBPF
RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

# Build libbpf as a static lib
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git && \
    cd libbpf-bootstrap && \
    git submodule update --init --recursive

RUN cd libbpf-bootstrap/libbpf/src && \
    make BUILD_STATIC_ONLY=y && \
    make install BUILD_STATIC_ONLY=y LIBDIR=/usr/lib/x86_64-linux-gnu/

# Clones the linux kernel repo and use the latest linux kernel source BPF headers 
RUN git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
    cp linux/include/uapi/linux/bpf* /usr/include/linux/

RUN git clone https://github.com/warmcat/libwebsockets --depth 1 && \
    cd libwebsockets && \
    mkdir build && cd build && \
    cmake -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITHOUT_TEST_SERVER=ON -DLWS_WITHOUT_TEST_SERVER_EXTPOLL=ON \
    -DLWS_WITHOUT_TEST_PING=ON -DLWS_WITHOUT_TEST_CLIENT=ON -DCMAKE_C_FLAGS="-fpic" -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make && make install && cd ..


RUN git clone https://github.com/yaml/libyaml --depth 1 --branch release/0.2.5 && \
    cd libyaml && mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_TESTING=OFF  -DBUILD_SHARED_LIBS=ON .. && \
    make && make install && cd ..

RUN git clone https://github.com/kubernetes-client/c --branch release-0.10 && \
    cd c/kubernetes && mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make && make install

RUN ldconfig

RUN mkdir /controller
ADD ./controller/timeloops /controller/timeloops

ENTRYPOINT /controller/timeloops
