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
sudo docker run -it --rm cbackyx/rapidpatch-ae:v2 /bin/bash
```

> Note that you can also choose to build the docker image on your own with the Dockerfile we provide. The Dockerfile will pull the code from our github repo. The github repo code function exactly the same as the code we have included in our prebuilt docker image. (The only difference is that we move `test_rapidpatch.sh` to the `/work/` dir for ease of test.)

> You can build the docker image with `sudo docker build -t XXX/rapidpatch-ae:v1 .`.

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
run 7: Invoke the vulnerable function for CVE-2020-17445 (Unbounded loop test)
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

> Notice: As hardware breakpoint is not supported in STM32 QEMU, shell commands other than fore-mentioned ones might not function correctly.

> Nevertheless, the fixed patch point approach is still hardware-independent.

The "run 5" command will invoke the vulnerable function at,   
https://github.com/IoTAccessControl/RapidPatch-Runtime-AE/blob/448fe8fdac6fa14b600257ddc85656af6f56e3a3/hotpatch/src/fixed_patch_points.c#L306  
Then a eBPF patch is loaded by the fixed patch point put at,   
https://github.com/IoTAccessControl/RapidPatch-Runtime-AE/blob/448fe8fdac6fa14b600257ddc85656af6f56e3a3/hotpatch/src/fixed_patch_points.c#L278  

If you have real devices, the patches can be added via hardware brakpoints. 

### UPDATE: November 14, 2021 

We also add a bug recovery example (CVE-2020-17445 reported in AMNESIA33) to demonstrate the need of unbounded loop in patch code and demonstrate the loop check we do. In detail, we port the vulnerable function, `pico_ipv6_process_destopt`, of PicoTCP stack. 

You can try to invoke the ported buggy function with

```
run 7
```

> For simplicity the buggy function is invoked with the patch code enabled.

```
run cmd: 7 {Invoke the vulnerable function for CVE-2020-17445}
init_patch_sys: 1
start to load patch: 3
load fixed patch AMNESIA33_cve_2020_17445 dummy_pico_ipv6_process_destopt_patch success!
addr ground-truth bug:0x08002a99 test:0x08002b35 
Patch instruction num 35
try to get patch at: 0x08002aa4
ret:0xffffffff
op code:0x00000001 
FILTER_DROP
The return code of the buggy function is 0
$ qemu: terminating on signal 15 from pid 29379
Built target qemu
```

The patch code for CVE-2020-17445 is as follows. It simulate the loop in the original vulnerable function `pico_ipv6_process_destopt` to check if the input data would cause an infinite loop.

```C
#include "ebpf_helper.h"

// PACKED_STRUCT_DEF pico_ipv6_exthdr {
//     uint8_t nxthdr;

//     PACKED_UNION_DEF ipv6_ext_u {
//         PEDANTIC_STRUCT_DEF hopbyhop_s {
//             uint8_t len;
//         } hopbyhop;

//         PEDANTIC_STRUCT_DEF destopt_s {
//             uint8_t len;
//         } destopt;

//         PEDANTIC_STRUCT_DEF routing_s {
//             uint8_t len;
//             uint8_t routtype;
//             uint8_t segleft;
//         } routing;

//         PEDANTIC_STRUCT_DEF fragmentation_s {
//             uint8_t res;
//             uint8_t om[2];
//             uint8_t id[4];
//         } frag;
//     } ext;
// };


uint64_t filter(stack_frame *frame) {
    uint32_t opt_ptr = (uint32_t)(frame->r2);
    opt_ptr += (uint32_t)(2u);
    uint8_t *destopt = (uint8_t *)(frame->r0);
    uint8_t *option = (destopt + 2);
    uint8_t len = (uint8_t)(((*(destopt + 1) + 1) << 3) - 2);
    uint8_t optlen = 0;
    uint32_t op = 0;
    uint32_t ret_code = 0;

    while (len) {
        optlen = (uint8_t)(*(option + 1) + 2);
        if (opt_ptr + optlen <= opt_ptr || option + optlen <= option || len - optlen >= len) {
            ret_code = -1;
            break;
        }
        opt_ptr += optlen;
        option += optlen;
        len = (uint8_t)(len - optlen);
    }

    if (ret_code != 0) {
        // intercept
        op = 1;
    }
    return set_return(op, ret_code);
}
```

To remove all the patch installed, input:

```
run 2
```
