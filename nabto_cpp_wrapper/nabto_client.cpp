#include "nabto_client.hpp"
#include <nabto/nabto_client.h>
#include <nabto/nabto_client_experimental.h>

namespace nabto {
namespace client {


int ConnectionEventsCallback::CONNECTED() {
    return NABTO_CLIENT_CONNECTION_EVENT_CONNECTED;
}


int ConnectionEventsCallback::CLOSED() {
    return NABTO_CLIENT_CONNECTION_EVENT_CLOSED;
}

int ConnectionEventsCallback::CHANNEL_CHANGED() {
    return NABTO_CLIENT_CONNECTION_EVENT_CHANNEL_CHANGED;
}

} }
