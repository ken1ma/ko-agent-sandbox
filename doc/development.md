# Tests

Run the commands in this section from the repository root.

## launcher

1. On the host, run the container-launching suites against the jar and images from
   [Build the launcher and images](../README.md#build-the-launcher-and-images). `test` and
   `testFull` skip these suites:

       sbt testWithPodman

    1. `testOnly` patterns can follow, quoted with the command:
       `sbt "testWithPodman *RunTopologyTest"`.
    1. One test is skipped unless `SIGNED_PUT_URL` holds a presigned S3 PUT URL for a
       bucket you own: the refusal of an owner-signed upload inside the inspected tunnel.

        1. The case's header in `src/test/scala/EgressSessionTest.scala` has the commands that sign
           the URL and the test command, which uses `sbt --server` so the variable reaches the
           tests.

1. On the host, start a sandbox with the default egress rules:

       KO_AGENT_SANDBOX_SESSION_START=immediate \
           java -jar target/dist/ko-agent-sandbox.jar bash

   Inside that session, run `sbt testFull`, which also runs `SessionBoundaryTest`.

1. `testFull` executes every test every time, unlike `test` which is incremental.

## egress-proxy

    (cd container/ko-agent-egress-proxy/app; sbt testFull)

## ko-agent-fs

    java -jar target/dist/ko-agent-sandbox.jar --self-test

1. `--self-test` runs the suite that needs no mount and the suite that mounts a real filter in a
   privileged container, on any machine with podman; running either suite directly is documented in
   [testing.md](../fuse/ko-agent-fs/doc/testing.md).


# Test environments

## On macOS

We develop on macOS, so tests run there without extra setup.


## On Linux aarch64

### tart VM

    brew trust --formula openai/tools/softnet  # tart's only dependency; it has none of its own
    brew install openai/tools/tart

    # Fedora 45 currently packages Podman 6.1.1 and OpenJDK 25.0.4
    # https://hotspot-nocache.fedoraproject.org/server/download/beta/
    (cd ~/Downloads; curl -fLO https://download.fedoraproject.org/pub/fedora/linux/releases/test/45_Beta/Server/aarch64/iso/Fedora-Server-dvd-aarch64-45_Beta-1.3.iso)

    # create a VM
    tart create --linux fedora-45-beta-1.3
    tart set fedora-45-beta-1.3 --cpu 8 --memory 16384 --disk-size 200
    tart run --disk ~/Downloads/Fedora-Server-dvd-aarch64-45_Beta-1.3.iso fedora-45-beta-1.3

### Fedora 45

1. In the VM
    1. Install Fedora 45
    1. English (United States)
    1. User Creation
        1. User name: admin
        1. Password: admin (the installer calls it weak; press Done twice)
    1. Installation Destination (keep the default, Automatic; press Done)
    1. Reboot System

1. On the host: when the VM shows the login prompt, stop `tart run` with Ctrl-C, then

       tart run --no-graphics fedora-45-beta-1.3

1. From another terminal: connect to the VM

       # set up ssh public key authentication
       [ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub
       ssh-copy-id -i ~/.ssh/id_ed25519.pub admin@$(tart ip fedora-45-beta-1.3)

       # ssh to the VM
       ssh admin@$(tart ip fedora-45-beta-1.3)

1. In the VM: upgrade the packages and skip the GRUB menu wait

       sudo dnf upgrade -y

       # GRUB hides its menu while `sudo grub2-editenv list` shows `boot_success=1`
       sudo grub2-editenv - set menu_auto_hide=1
       systemctl --user edit grub-boot-success.timer

    1. Insert the following

           [Timer]
           # clear the default of 2min
           OnActiveSec=
           # set `boot_success=1` as soon as `admin` logs in
           OnActiveSec=0

    1. Shut down the VM

           sudo poweroff

### The test image

1. On the host: clone the VM

       tart clone fedora-45-beta-1.3 ko-agent-test-fedora-45
       tart run --no-graphics ko-agent-test-fedora-45

1. Connect

       ssh admin@$(tart ip ko-agent-test-fedora-45)

1. In the VM: set up

       sudo dnf install -y java-25-openjdk-headless git

       curl -fsSL "https://github.com/coursier/launchers/raw/master/cs-$(uname -m)-pc-linux.gz" | gzip -d > cs
       chmod +x cs
       ./cs setup --apps cs,scala,scalac,sbt,sbtn,scalafmt
       exit  # log in again to load ~/.bash_profile

    1. `podman` and `passt` are already installed.
        1. Rootless podman uses `pasta` from the `passt` package for networking.
    1. `--apps` lists coursier's default apps without two redundant launchers.
        1. `scala-cli` is omitted: the Scala distribution behind `scala` bundles the same Scala CLI
           native image.
        1. `coursier` is omitted: it is the JAR-based fallback, and `cs` has a native launcher for
           both aarch64 and x86_64.

### Set up the sandbox

#### Clone the repository

In the VM:

    git clone https://github.com/ken1ma/ko-agent-sandbox.git
    cd ko-agent-sandbox

Alternatively, on the host: copy the worktree

    rsync -a --delete --exclude target . admin@$(tart ip ko-agent-test-fedora-45):ko-agent-sandbox

#### In the VM

1. Append `user_allow_other` to `/etc/fuse.conf`

       sudo sh -c 'echo user_allow_other >> /etc/fuse.conf'

   Without this, `--build` fails with

       ko-agent-fs self-test failed in its setup, before any check: mount failed:
       fusermount3: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf

1. Build the container images

       sbt dist && java -jar target/dist/ko-agent-sandbox.jar --build

1. Run the sandbox

       java -jar target/dist/ko-agent-sandbox.jar bash


## On Linux x86_64


## On Windows x64

1. We use EC2.
1. QEMU on Apple silicon does not work: the
   [Windows 11 Enterprise 25H2 x64 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
   runs for 90 days without a product key, but QEMU TCG is very slow and does not support the
   nested virtualization podman needs.
