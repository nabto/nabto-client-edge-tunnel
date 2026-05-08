# Nabto Edge Tunnel CLI
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
libraries. These consist of some headers and some libraries copied
into this repository from the
[nabto-client-sdk-releases](https://github.com/nabto/nabto-client-sdk-releases)
repo. The directory layout mirrors that release repo:

  * linux x86-64 `lib/linux-x86_64/libnabto_client.so`
  * mac universal `lib/macos-universal/libnabto_client.dylib`
  * windows x86-64 `lib/windows-x86_64/nabto_client.lib` `lib/windows-x86_64/nabto_client.dll`
  * common headers `include/nabto/nabto_client.h` `include/nabto/nabto_client_experimental.h`
