## RapidPatch Artifact Overview  
This artifact contains the source code of RapidPatch and the stuff for running it. Since RapidPatch is designed for hotpatching embedded devices, to evaluate the basic functions, you need to have a Cortex-M3/M4 based arm development board. If you do not have these devices, we also provide a simple version that can run on qemu, and can demonstrate the functionable of RapidPatch by running the hotpatching process using fixed patch points (only one of the three hotpatching strategies supported by our tool). To fully evaluate and reproduce the results, you need to have at least one of these STM32L475/STM32F429/Nrf52840 developing boards. Note that you can use any of the MacOS/Windows/Linux Platform to evaluate our tool, since we provide Docker and PlatformIO-based VSCode cross-platform building environments.  

This repositories contains the source code of RapidPatch and the corresponding evaluate code used in our paper. Based on the design in our paper, we put different modules in three sub-modules,    
- RapidPatch Runtime:   contains the core library of RapidPatch that can be easily port to different RTOS and devices.  
- RapidPatch Toolchain: constains the toolchain for generate and verify the bytecode patch.  
- RapidPatch VulDevices: test devices used for evaluation in our paper.    

### Avaiable
The formal version of RapidPatch will released soon in the master branch. We plan to remove the redundant test code and re-organize the code.    
https://github.com/IoTAccessControl/RapidPatch/tree/master    

We put the version used in our paper on the  ArtifactEvaluation branch.  you can use it to perform the artifact evaluation.    

```
git clone https://github.com/IoTAccessControl/RapidPatch.git
cd RapidPatch
git submodule update --init --recursive
```



### Validate the Functionable

#### Using Qemu

Follow the [document](Docker/docker-qemu.md) for Qemu.

#### Using real devices

You should have at least one devices with the following MCUs,  

- NRF52840  
- STM32F429
- STM32L475 

We put all the RTOS/Library real devices projects in the RapidPatch-VulDevices-AE repository.  If you want to build the firmware from scratch, you can find some guides in the README of RapidPatch-VulDevices-AE. Since building the RTOS projects is trivial and challenge, we failed to put enough technical details in the documents. If you meet any difficult, please do not hesitate to drop us an email.

```
heyi21@mails.tsinghua.edu.cn or clangllvm@126.com
zou-zh21@mails.tsinghua.edu.cn
```



Note that you can also use the pre-build firmware to run on NRF52840 projects.  


### Validate the Reproduceable
We highly suggest the reviewers use the prebuilts (images) we provide under folder `./board-prebuilts` to evaluate RapidPatch on the NRF52840 development board directly.

* In detail, we provide three prebuilt Zephyr OS (v1.14.1) images (integrated with RapidPatch) and the evaluation tools for each of them. These are actually also part of our system overhead evaluation.

  * The three images run three different applications (MQTT, CoAP, USB Mass Storage) separately, and correspond to CVE-2020-10062, CVE-2020-10063, CVE-2020-10021 respectively.

* The detailed introductions and instructions for flashing and evaluating each image are placed at corresponding sub folders.
