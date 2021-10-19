import usb.core
import struct
import time
import os

filesize = []
timeused = []

def p32(x):
    return struct.pack("<I", x)

def p32b(x):
    return struct.pack(">I", x)

def p8(x):
    return struct.pack("<B", x)

def perf_test(dev):

    global timeused
    global filesize

    for i in range(10000):
        print(i)
        tic = time.perf_counter()
        # for j in range(100):
            # print("hhh")
        cb = p8(0xAA) + p8(0) + p32b(0) + p32b(1)
        cbw = b"USBC" + p32(0x11223344) + p32(0x200) + p8(0) + p8(0) \
            + p8(len(cb)) + cb

        cbw += b"\x00" * (31 - len(cbw))
        dev.write(1, cbw)

        dev.write(1, b"\x00" * 0x200)

        # time.sleep(0.1)

        dev.clear_halt(1)

        dev.read(0x81, 0x40)
        
        dev.ctrl_transfer(0x20, 0xFF, 0, 0)
        
        cb = p8(0xA8) + p8(0) + p32b(0) + p32b(1)
        cbw = b"USBC" + p32(0x11223344) + p32(0x200) + p8(0x80) + p8(0) \
            + p8(len(cb)) + cb

        cbw += b"\x00" * (31 - len(cbw))
        dev.write(1, cbw)
        data = bytes(dev.read(0x81, 0x200))

        dev.read(0x81, 0x40)
        toc = time.perf_counter()
        interval = toc - tic
        filesize.append(i + 1)
        timeused.append(interval)
        
    return data

def hexdump(data):
    line = ""
    for x, b in enumerate(data):
        if x % 16 == 0 and line:
            print(line)
            line = ""
        line += "{:02X} ".format(b)

    if line:
        print(line)

def load_backend():
    from usb.backend import libusb1, libusb0
    backend = libusb1.get_backend()
    # backend = libusb0.get_backend()
    print(backend)
    return backend

def main():
    dev = usb.core.find(idVendor=0x2fe3, idProduct=0x0100)

    for cfg in dev:
        # print(cfg)
        for intf in cfg:
            if dev.is_kernel_driver_active(intf.bInterfaceNumber):
                try:
                    dev.detach_kernel_driver(intf.bInterfaceNumber)
                except usb.core.USBError as e:
                    raise RuntimeError("detach_kernel_driver")
    
    try:
        data = perf_test(dev)
        hexdump(data)
    except Exception:
        a = 1
        print(Exception)

    print(len(timeused))
    with open("perf_usbmass_without_patch.txt", "w", encoding= "utf-8") as ofile:
        for i in range(len(timeused)):
            ofile.write(str(timeused[i]) + "\n")

if __name__ == "__main__":
    main()