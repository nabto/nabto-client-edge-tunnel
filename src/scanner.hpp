#pragma once

#include <nabto_client.hpp>

#include <vector>
#include <chrono>
#include <thread>
#include <memory>
#include <set>

namespace nabto {
namespace examples {
namespace common {

class Scanner {
 public:
    static std::vector<std::tuple<std::string,std::string> > scan(std::shared_ptr<nabto::client::Context> ctx, std::chrono::milliseconds timeout) {

        // We put the found devices into a set such that we can remove ipv4/ipv6 duplicates.
        std::set<std::tuple<std::string, std::string> > localDevices;
        auto mdnsResolver = ctx->createMdnsResolver();

        std::thread t([mdnsResolver, timeout]() { std::this_thread::sleep_for(timeout); mdnsResolver->stop(); });

        try {
            for (;;) {
                auto next = mdnsResolver->getResult();
                auto result = next->waitForResult();
                std::string productId = result->getProductId();
                std::string deviceId = result->getDeviceId();
                localDevices.insert(std::make_tuple(productId, deviceId));
            }
        } catch (...) {

        }

        t.join();

        std::vector<std::tuple<std::string, std::string> > ret;
        for (auto d : localDevices) {
            ret.push_back(d);
        }
        return ret;
    }
};

} } } // namespace
