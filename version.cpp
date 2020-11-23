#include "version.hpp"

static const char* version_str = "1.0.0-master.75+fb6e253.dirty"
;
const char* edge_tunnel_client_version() { return version_str; }
