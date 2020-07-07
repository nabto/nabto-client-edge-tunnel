#include "nabto_client_impl.hpp"


namespace nabto {
namespace client {

ConnectionEventsListenerImpl::ConnectionEventsListenerImpl(NabtoClient* context, NabtoClientConnection* connection, std::shared_ptr<ConnectionImpl> connectionImpl)
    : connection_(connection), connectionImpl_(connectionImpl)
{
    future_ = nabto_client_future_new(context);
    listener_ = nabto_client_listener_new(context);
}

ConnectionEventsListenerImpl::~ConnectionEventsListenerImpl() {
    nabto_client_listener_free(listener_);
    nabto_client_future_free(future_);
}
void ConnectionEventsListenerImpl::futureCallback(NabtoClientFuture* future, NabtoClientError ec, void* data) {
    ConnectionEventsListenerImpl* listener = (ConnectionEventsListenerImpl*)data;
    if (ec == NABTO_CLIENT_EC_OK) {
        auto connection = listener->connectionImpl_.lock();
        if (connection) {
            connection->notifyEvent((int)listener->event_);
            listener->listen();
        }
    }
}

} }
