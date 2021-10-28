## Run RapidPatch in QEMU

### Overview

We provide a simplest demo of RapidPatch functionality in [STM32 QEMU](https://github.com/beckus/qemu_stm32). 

As QEMU does not simulate the hardware breakpoint feature, in this demo, we choose the hardware-independant trigger, i.e., fixed patch point.

Nevertheless, to better show how actually RapidPatch works, we port the vulnerable function of [CVE-2020-10062](https://nvd.nist.gov/vuln/detail/CVE-2020-10062) in [Zephyr OS](https://www.zephyrproject.org/) to a non-OS App and patch it using the fixed patch point.

Reviewers are encouraged to build and run this patch demo using the docker image we provide.

### How to Run

First, download the docker image and run. (~10 min, depends on your network status)

> Docker version: >19.x

```bash
sudo docker run -it --rm cbackyx/rapidpatch-ae:v1 /bin/bash
```

Now we have entered the docker bash. Make sure that you are under the folder `/work`. Then, type: (~10 sec)

```bash
source test_rapidpatch.sh
```

You can see from the log that the build process of RapidPatch and the demo app has been triggered automatically. And finally you enter a shell in QEMU. If you see the following hints, congratulation! You have compiled and flashed the image on QEMU successfully!

```
LED Off
Start Qemu Test
IoTPatch Cli Usage: run [idx] | trigger [cve] | patch [cve] | vm [vid]
run 0: Test FPB breakpoint add
run 1: Test FPB patch trigger
run 2: Clear all bpkt and patch
run 3: Run eva test
run 4: Start patch service
run 5: Invoke the vulnerable function for CVE-2020-10062
run 6: Load patch at the fixed patch point for CVE-2020-10062
```

Then, just type as follows into the shell to invoke the unpatched vulnerable function: (~1 sec)

```
run 5
```

The following log indicate that the vulnerable function is not patched.

```
run cmd: 5 {Invoke the vulnerable function for CVE-2020-10062}
addr ground-truth bug:0x08002915 test:0x080029b1 
Patch instruction num 5295
try to get patch at: 0x0800291c
Do not find Patch here
dummy MQTT packet length:0xffffffff 
Decoded MQTT packet length is -1
The buggy function is still vulnerable!
```

Now you can patch the vulnerable function with:

```
run 6
```

If you see the following hints, it means that you have installed and activated a patch at the fixed patch point for this vulnerable function.

```
run cmd: 6 {Load patch at the fixed patch point for CVE-2020-10062}
start to load patch: 2
load fixed patch zephyr_cve_2020_10062 dummy_MQTT_packet_length_decode_patch success!
```

Now, to check if the function has been patched, input:

```
run 5
```

Again, if you see the following hints, it means that the malicious inputs to the vulnerable function of CVE-2020-10062 have been blocked by the fixed patch point we intrumented.

```
run cmd: 5 {Invoke the vulnerable function for CVE-2020-10062}
addr ground-truth bug:0x08002915 test:0x080029b1 
Patch instruction num 60
try to get patch at: 0x0800291c
ret:0xffffffea
op code:0x00000001 
FILTER_DROP
Decoded MQTT packet length is 0
The buggy function is fixed!
```

> Notice: As hardware breakpoint is not supported in STM32 QEMU, shell commands other than `run 5` might not function correctly.

To remove all the patch installed, input:

```
run 2
```

The "run 5" command will invoke the vulnerable function at,   
https://github.com/IoTAccessControl/RapidPatch-Runtime-AE/blob/448fe8fdac6fa14b600257ddc85656af6f56e3a3/hotpatch/src/fixed_patch_points.c#L306  
Then a eBPF patch is loaded by the fixed patch point put at,   
https://github.com/IoTAccessControl/RapidPatch-Runtime-AE/blob/448fe8fdac6fa14b600257ddc85656af6f56e3a3/hotpatch/src/fixed_patch_points.c#L278  

If you have real devices, the patches can be added via hardware brakpoints. 
