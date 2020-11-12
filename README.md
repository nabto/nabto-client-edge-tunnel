# Nabto Client Edge Tunnel
Tunnelling client application for Nabto Edge

## Building

```
mkdir _build
cmake -DCMAKE_INSTALL_PREFIX=../_install ..
cmake --build . --config Release --target install
../_install/edge_tunnel_client --help
```

The Nabto Client Edge Tunnel is now ready to pair with a TCP Tunnel
Device. For a step-by-step guide on how to pair with a device see
our
[TCP Tunnelling Quick Start](https://docs.nabto.com/developer/guides/get-started/tunnels/quickstart.html).
