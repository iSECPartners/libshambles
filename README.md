# Overview

libshambles is a TCP interception library that hooks established TCP streams
and provides `send(2)`/`recv(2)`-able socket interfaces to communicate with the
connection's peers. It was primarily developed to intercept highly dynamic
network protocols at scale. 

libshambles is designed to be minimal and allow the use of privilege
minimization and separation, and sandboxing techniques and technologies. Once
passed sufficient information about a TCP stream to intercept, libshambles will
generate sockets with forged TCP state data so as to trick the kernel into
recognizing the stream's packets as ones intended for it. It then modifies the
firewall and connection tracking state to cleanly split the client-to-server
connection into two separate ones, client-to-interceptor and
interceptor-to-server. It additionally contains code to pass the sockets to
other processes via Unix domain sockets and also contains teardown
functionality to undo the firewall modifications once the intercepted
connection is finished.

libshambles is written in C++ (compiled as C++14), but provides C bindings for
its public API. It is released under a two-clause BSD license.

For more information, see my 
[blog post](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/october/libshambles)
introducing libshambles and the rationale behind it.

# Quickstart

As libshambles is a library and also needs to be supplied accurate TCP/IP
connection information (e.g. IP addresses, ports, SEQ/ACK numbers), the
libshambles codebase is highly limited. However, this repository contains a
sample toolchain leveraging libshambles, which consists of a libpcap daemon, an
interceptor using
libshambles, and Python/Ruby scripts wrapping a native (C++14) file descriptor
accepting daemon. These tools are provided in the `samples` directory. You'll
probably want to run the following across three separate terminal sessions:

## WARNING

The `scan` and `shambles` daemons currently communicate over an unauthenticated
plaintext connection (IPv4/TCP). You should be careful not to expose the
`shambles` listener to the local network. Also be careful with respect to
anything on the host running it, as  they would be able to abuse its
functionality.

#### Compile and load the `forge_socket` kernel module, load the `nf_conntrack_ipv4` module, and build libshambles:
```bash
$ git clone https://github.com/iSECPartners/libshambles
$ git submodule init
$ git submodule update
$ cd vendor/forge_socket
$ make
$ sudo insmod forge_socket.ko
$ sudo modprobe nf_conntrack_ipv4
$ cd ../../
$ make
```

#### Setup libuv, and compile and run the `shambles` daemon:
```bash
$ cd /path/to/libshambles
$ cd samples/shambles
$ sh setup_libuv.sh
$ make
$ mkdir /tmp/shambles
$ sudo ./nat.sh <external interface> <internal interface> <internal network> [blacklist network]
$ sudo ./shambles <external IP> <internal IP> <LAN netmask> /tmp/shambles/shambles_sock <bind address> <bind socket>
```

#### Compile and run the `scan` daemon:
```bash
$ cd /path/to/libshambles
$ cd samples/scan
$ make
$ sudo ./scan <internal interface> '<bpf filter>' '<search regex>' <shambles bind address> <shambles bind socket>
```

#### Compile the `hookffi` shared library, and use Python to hook stuff:
```bash
$ cd /path/to/libshambles
$ cd samples/hookffi
$ make
$ nano hook.py # add in whatever you want to the custom_hook function
$ python hook.py /tmp/shambles_sock root
```
If Ruby is more your thing than Python, edit the `custom_hook` method in
`hook.rb` instead and run:

```bash
$ ruby hook.rb /tmp/shambles_sock root
```

Next, make a plaintext TCP connection from a host behind the one running the
sample tools (and out to a remote host) that will match both the bpf filter and
search regex passed to the `scan` daemon. Observe that your code will hook the
connection and read and write to both the local client and remote host.


# Dependencies
libshambles itself has a couple of dependencies and the samples depend on
various other projects like libpcap and libuv. Additionally, as I developed
libshambles on Ubuntu 14.04, it relies on Clang and libc++ for modern C++
support needed to compile and run it.

On Ubuntu 14.04, the below `apt-get` one-liner should get you most of the way
there.
```bash
$ sudo apt-get install build-essential git libpcap-dev libmnl-dev libcap-dev libc++-dev libc++abi1 libc++1 libtool automake autotools-dev
```
You'll also need to grab Clang from the LLVM
[releases page](http://llvm.org/releases/download.html). I usually
extract it out to `/opt/clangllvm` on my machine and then prepend that to my
`$PATH`, but do as you like.

Other dependencies are covered in the above quickstart instructions.

# Versioning
libshambles uses semantic versioned tag branches. In general, this means that
the version format is `major.minor.patch`, where major version updates include
backwards compatibility changes (and/or other major changes), minor version
updates include new features that don't break the API and possibly
deprecations, and patch version updates fix bugs. Please note that depending on
the bugs fixed, it may be necessary to increment the minor or even major
version number. Any such instances will be clearly marked should they occur by
a clear note in the `CHANGELOG` file. For now, and likely the foreseeable
future, I intend only to fix bugs in the current `major.minor` branch. For
example, should a `1.2.0` release come out following `1.1.8`, there will not be
a `1.1.9` release containing backported fixes for the `1.1.x` branch.

# Future Work
- IPv6
    - this will likely require setting up DNAT/SNAT in both directions due to
      the lack of NAT in IPv6 (in IPv4+NAT it is only needed for the inner
      host)

- FreeBSD support:
    - port forge_socket to FreeBSD
    - implement analogous connection tracking stuff (e.g. equivalents for
      netfilter conntrack functionality)
    - convert firewall rules
        - likely support IPFW, FreeBSD's pf is more limited for these things

- Unit tests

- Integration with highly advanced PCAP daemons
  (e.g. [Net Sensor](https://isis.poly.edu/~bk/netsensor/))

- Detection/Anti-Detection research
    - Profile TCP for options differences
        - Perform better TCP state forgery to eliminate obvious differences
    - Profile connections for midstream implementation differences (e.g. why
      did the host/client stop speaking TCP like X and why is it now speaking
      TCP like Linux?)
        - Research mitigations

- (Wishful thinking) Modifying the DPDK/netmap TCP engines to perform similar
  functionality


# Contributing & Bug Reporting

Feel free to send pull requests or even just add an issue if you spot a bug (or
would like to make a feature request). If you happen to find any security
issues, please contact me directly at `jeff.dileo@nccgroup.trust` (my PGP key is
available [here](https://isecpartners.github.io/keys/jdileo.asc)) instead of
filing an issue.
