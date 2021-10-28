FROM ubuntu:20.04
LABEL maintainer="Yi He, Zhenhua Zou"
LABEL Description="Image for building and testing RapidPatch on STM32 QEMU"
WORKDIR /work

ARG DEBIAN_FRONTEND="noninteractive"

# Install any needed packages specified in requirements.txt
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
# Development files
      build-essential \
      git make cmake \
      bzip2 \
      wget && \
    apt-get clean

RUN wget -qO- https://developer.arm.com/-/media/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2 | tar -xvj

# Build QEMU STM32

RUN apt-get install -y build-essential python zlib1g-dev libglib2.0-dev libpixman-1-dev libtool libfdt-dev

# RUN git clone https://github.com/beckus/qemu_stm32.git
RUN wget https://github.com/beckus/qemu_stm32/archive/refs/tags/stm32_v0.1.3.zip

RUN apt-get install unzip && \
    unzip stm32_v0.1.3.zip

# RUN cd /work/qemu_stm32 && \
#     ./configure --disable-werror --enable-debug \
#         --target-list="arm-softmmu" \
#         --extra-cflags=-DSTM32_UART_NO_BAUD_DELAY \
#         --extra-cflags=-DSTM32_UART_ENABLE_OVERRUN \
#         --disable-gtk && \
#     make


RUN cd qemu_stm32-stm32_v0.1.3/ && \
    ./configure --disable-werror --enable-debug \
        --target-list="arm-softmmu" \
        --extra-cflags=-DSTM32_UART_NO_BAUD_DELAY \
        --extra-cflags=-DSTM32_UART_ENABLE_OVERRUN \
        --disable-gtk && \
    make
    
ENV PATH "/work/gcc-arm-none-eabi-9-2020-q2-update/bin:$PATH"
ENV PATH "/work/qemu_stm32-stm32_v0.1.3/arm-softmmu:$PATH"

# ADD . /work

RUN git clone https://github.com/IoTAccessControl/RapidPatch.git --recursive && \
    cd RapidPatch/VulDevices/qemu-stm32-p103/ &&\
    mkdir build && \
    cd build && \
    cmake .. && \
    make qemu   

# RUN cd /work/IoTPatch/VulDevices/qemu-stm32-p103/ && \
#     rm -r build && \
#     mkdir build && \
#     cd build && \
#     cmake .. && \
#     make qemu