from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.layers.http import *
import os
import time

tic = 0
toc = 0

ofile = open("mqtt_macro_overhead_fixed_patch.txt", "a", encoding='utf-8')

def callback(pkt):
    # print("h")
    global tic
    global toc
    if pkt.haslayer(TCP):
        if pkt.haslayer(MQTTPublish):
            tic = time.perf_counter()
        if pkt.haslayer(MQTTPuback):
            toc = time.perf_counter()
            interval = toc - tic
            print(interval)
            ofile.write(str(interval) + '\n')
            tic = 0
            toc = 0
            

try:
    sniff(filter='tcp', prn=callback, store=0, iface='enx00005e005301')
except:
    ofile.close()


    

