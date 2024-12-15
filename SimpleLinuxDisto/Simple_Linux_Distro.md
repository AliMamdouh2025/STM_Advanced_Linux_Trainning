# Create Linux System Distro on QEMU ARM

🔧 This guide outlines the steps to create a minimalistic Linux system using QEMU, ARM architecture, the Linux kernel, and BusyBox. It includes instructions on compiling the kernel, creating a root filesystem (RootFS), and running the system on QEMU ARM Versatile PB board.

## Table of Contents

- 📜 [Overview](#overview)
- ⚙️ [Prerequisites](#prerequisites)
- 🏗️ [Steps to Build](#steps-to-build)
  - 🐧 [Install QEMU](#install-qemu)
  - 🖥️ [Kernel Setup](#kernel-setup)
  - 🗃️ [BusyBox Setup](#busybox-setup)
  - 📂 [Creating the RootFS](#creating-the-rootfs)
  - 💻 [Running the System on QEMU](#running-the-system-on-qemu)
- 📋 [Notes](#notes)
- 🎥 [References](#references)
- ✍️ [Video](#Video)

## Overview

📁 This project walks through the process of setting up a Simple Linux distrobution using QEMU and the ARM architecture. You will:
- Install necessary tools and cross-compilers.
- Compile the Linux kernel for the ARM architecture.
- Set up BusyBox to provide Unix utilities.
- Create a compressed root filesystem (RootFS).
- Run the system on QEMU with a custom init process.

The steps follow [this guide](https://lukaszgemborowski.github.io/articles/minimalistic-linux-system-on-qemu-arm.html).

## Prerequisites

Before starting, make sure to install the necessary tools and dependencies.

### Required Packages
- QEMU (for ARM architecture emulation)
- Cross-compilation tools (for building the kernel)
- Linux kernel source code
- BusyBox (for basic Unix utilities)

Install these dependencies on a Linux machine:

```bash
# Install QEMU
sudo apt install qemu-system-arm

# Install kernel compilation prerequisites
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison

# Install the ARM cross-compiler
sudo apt install gcc-arm-linux-gnueabi
```

## Steps to Build

### Install QEMU

We will use the QEMU ARM Versatile PB board, which simulates a versatile platform:
- [ARM Versatile PB Documentation](https://www.qemu.org/docs/master/system/arm/versatile.html)

```bash
sudo apt install qemu-system-arm
```

### Kernel Setup

1. **Download the Latest Linux Kernel**  
   Obtain the latest kernel from [kernel.org](https://www.kernel.org/).

   ```bash
   # Untar the kernel
   tar xvf linux-6.11.1.tar.xz 
   ```

2. **Configure the Kernel**  
   Configure the kernel for ARM architecture and the vexpress_defconfig.

   ```bash
   cd linux-6.11.1
   make O=./build/ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- vexpress_defconfig
   ```

3. **(Optional) Modify the Kernel Configuration**  
   You can modify the kernel configuration using `menuconfig`.

   ```bash
   make O=./build/ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- menuconfig
   ```

4. **Build the Kernel and Modules**  
   Compile the kernel and the modules.

   ```bash
   time make -j8 O=./build/ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-
   time make -j8 modules O=./build/ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-
   ```

5. **Install the Kernel Modules**  
   Install the modules into the RootFS.

   ```bash
   time make -j8 modules_install O=./build/ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- INSTALL_MOD_PATH=../rootfs
   ```

6. **Check Installed Modules**  
   View the installed kernel modules.

   ```bash
   cd ../rootfs
   find . -name "*.ko"
   ```

### BusyBox Setup

1. **Download BusyBox**  
   Download the latest BusyBox from [BusyBox.net](https://busybox.net/).

2. **Compile BusyBox**  
   Configure and build BusyBox to get essential Unix utilities.

   ```bash
   # Configure BusyBox
   make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- defconfig
   make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- menuconfig
   # Under settings, choose "Build BusyBox as a static binary"
   
   # Build and install BusyBox
   make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j8
   make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- install
   ```

### Creating the RootFS

1. **Create the Root Filesystem (RootFS)**  
   Set up the RootFS with the necessary directories and create the `init` script.

   ```bash
   cd rootfs
   vim rootfs/init  # Add the following content:
   ```

   ```sh
   #!/bin/sh
   echo -e "\nHello from the init process\n"
   
   mount -tproc none /proc
   mount -tsysfs none /sys
   mknod -m660 /dev/mem c 1 1

   exec /bin/sh
   ```

   2. **Make the `init` File Executable**  
   ```bash
   chmod +x rootfs/init
   ```

3. **Copy BusyBox Files**  
   Copy the BusyBox binaries to the RootFS.

   ```bash
   cp -av busybox-1.36.1/_install/* rootfs/
   mkdir -pv rootfs/{bin,sbin,etc,proc,sys,usr/{bin,sbin}}
   ```

4. **Compress the RootFS**  
   Compress the RootFS into a cpio archive.

   ```bash
   cd rootfs/
   find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../rootfs.cpio.gz
   ```

### Running the System on QEMU

Now you can run the system on QEMU with the created RootFS:

```bash
qemu-system-arm -M vexpress-a9 -kernel ./linux-6.11.1/build/arch/arm/boot/zImage -dtb ./linux-6.11.1/build/arch/arm/boot/dts/vexpress-v2p-ca9.dtb -initrd ./rootfs.cpio.gz -serial stdio -append "root=/dev/mem serial=ttyAMA0"
```

## Notes

📋 The Simple Linux system boots with a custom kernel and BusyBox-based utilities. The `init` script in the RootFS handles the initial process setup, mounting filesystems, and starting an interactive shell.



## References

🎥 Original tutorial and steps are based on this [guide](https://lukaszgemborowski.github.io/articles/minimalistic-linux-system-on-qemu-arm.html).


## Video
[Create Simple Linux Distro](https://drive.google.com/file/d/18MadZP0T-1Fv_JE_2m6F_emJLxGolDS6/view?usp=drive_link)
