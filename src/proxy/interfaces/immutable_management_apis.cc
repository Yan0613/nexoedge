// SPDX-License-Identifier: Apache-2.0

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>

#include "./immutable_management_apis.hh"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

ImmutableManagementApis::ImmutableManagementApis(std::shared_ptr<ImmutableManager> immutableManager) : _immutableManager(immutableManager) {
    // TODO run an instance of the RESTful API service
}

ImmutableManagementApis::~ImmutableManagementApis() {
}

