# Nabto Client Edge Tunnel
Tunnelling client application for Nabto Edge

## Building

```
mkdir _build
cd _build
cmake -DCMAKE_INSTALL_PREFIX=../_install ..
cmake --build . --config Release --target install
../_install/edge_tunnel_client --help
```

The Nabto Client Edge Tunnel is now ready to pair with a TCP Tunnel
Device. For a step-by-step guide on how to pair with a device see
our
[TCP Tunnelling Quick Start](https://docs.nabto.com/developer/guides/get-started/tunnels/quickstart.html).


## Nabto Edge Client Libraries

The tunnel client application depends on the Nabto Edge Client
libraries. These consists of some headers and some libraries. These
files are copied to this repository from the nabto edge client
release.

  * linux x86-64 `lib/linux/libnabto_client.so`
  * mac x86-64 `lib/macos/libnabto_client.dylib`
  * windows x86-64 `lib/windows/nabto_client.lib` `lib/windows/nabto_client.dll`
  * common headers `include/nabto_client.h` `include/nabto_client_experimental.h`
