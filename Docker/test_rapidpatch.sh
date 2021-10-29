cd /work/VulDevices/qemu-stm32-p103/
[ -d build ] && rm -r build
mkdir build && \
    cd build && \
    cmake .. && \
    make qemu