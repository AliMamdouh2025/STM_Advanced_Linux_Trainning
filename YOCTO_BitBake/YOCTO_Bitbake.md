# Introduction To YOCTO

🔧 This guide covers the pre-development stage of setting up a YOCTO build environment, including preparing the host machine, choosing the appropriate YOCTO release, testing the environment using QEMU, and building a minimal image.

## Table of Contents

- 📜 [Overview](#overview)
- ⚙️ [Prerequisites](#prerequisites)
- 🏗️ [Steps to Set Up](#steps-to-set-up)
  - 🖥️ [Prepare Environment](#prepare-environment)
  - 🛠️ [Clone YOCTO Release](#clone-yocto-release)
  - 🧪 [Test Environment with QEMU](#test-environment-with-qemu)
  - 🖼️ [Build Minimal Image](#build-minimal-image)
- 📋 [Notes](#notes)
- 🎥 [Bitbake_Tutorial](#Bitbake_Tutorial)
- ✍️ [Video](#Video)

## Overview

📁 This document guides you through the pre-development setup for YOCTO, including preparing your host machine and testing the environment with QEMU. You will:
- Set up required dependencies on your host machine.
- Clone the YOCTO release.
- Configure and test the environment with QEMU.
- Build a minimal YOCTO image.

## Prerequisites

Before starting, ensure that your host machine meets the necessary system requirements and has the appropriate dependencies installed.

### Required Packages

Install the following dependencies on your host machine:

```bash
sudo apt install gawk wget git diffstat unzip texinfo gcc build-essential chrpath socat \
cpio python3 python3-pip python3-pexpect xz-utils debianutils iputils-ping python3-git \
python3-jinja2 libegl1-mesa libsdl1.2-dev python3-subunit mesa-common-dev zstd \
liblz4-tool file locales libacl1
```

Make sure your locale is set correctly:

```bash
sudo locale-gen en_US.UTF-8
```

For more information on system requirements, refer to the official documentation:
[YOCTO System Requirements](https://docs.yoctoproject.org/ref-manual/system-requirements.html)

## Steps to Set Up

### Prepare Environment

To set up your environment, you first need to install the required dependencies and configure your host machine. This ensures that the necessary packages are available for running YOCTO builds and tests.

### Clone YOCTO Release

1. **Choose a YOCTO release**  
   You can browse available YOCTO releases here:  
   [YOCTO Releases](https://wiki.yoctoproject.org/wiki/Releases)

2. **Clone the YOCTO repository**  
   Clone the `poky` repository from GitHub, specifying the desired branch (in this case, `Scarthgap`).

   ```bash
   git clone -b Scarthgap https://github.com/yoctoproject/poky.git
   cd poky
   ```

### Test Environment with QEMU

After setting up the environment, you can test the setup with QEMU by sourcing the `oe-init-build-env` script and running the required configuration steps.

1. **Source the environment script**

   ```bash
   source oe-init-build-env
   ```

   This script prepares the environment and adds required paths to allow you to use YOCTO commands like `runqemu` and `bitbake`.

2. **Modify local configuration**

   Navigate to the `conf` directory and open the `local.conf` file:

   ```bash
   cd conf
   vi local.conf
   ```

3. **Set the machine type**  
   Modify the `MACHINE` variable to specify the target architecture (e.g., `qemuarm`).

   ```bash
   MACHINE ??="qemuarm"
   ```

4. **Set the number of threads**  
   Adjust the number of threads to optimize the build process according to your machine's specifications. The number should typically be half the number of CPU cores on your machine(use lscpu command to know number of your cores).

   ```bash
   BB_NUMBER_THREADS="6"
   PARALLEL_MAKE="-j 6"
   ```

### Build Minimal Image

1. **Build the minimal image**  
   Use `bitbake` to build the core image (in this case, `core-image-minimal`):

   ```bash
   bitbake core-image-minimal
   ```

2. **Run the built image using QEMU**  
   After building the image, use `runqemu` to launch QEMU with the specified machine configuration:

   ```bash
   runqemu <MACHINE> <option>  # e.g., runqemu qemuarm nographic
   ```

## Notes

📋 Once your setup is complete, you should have a minimal YOCTO system ready to run on QEMU with the selected machine type (`qemuarm` in this case). The `bitbake` tool is used to build the core image, and the `runqemu` command launches the QEMU virtual machine with the specified settings.

## Bitbake_Tutorial

🎥 To learn more about using `bitbake` and setting up YOCTO, refer to the official BitBake tutorial:  
[BitBake Guide](https://a4z.gitlab.io/docs/BitBake/guide.html)

## Video

✍️ You can watch my video covers building and testing a YOCTO image here:  
[MyVideo](https://drive.google.com/file/d/1dvASqV8TAXeK-px1aI9IAFVDup4PDdRK/view?usp=drive_link)
