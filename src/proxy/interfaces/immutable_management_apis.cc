// SPDX-License-Identifier: Apache-2.0

#include <nlohmann/json.hpp>

#include "../../common/config.hh"

#include "./immutable_management_apis.hh"

// http server: https://live.boost.org/doc/libs/1_74_0/libs/beast/example/http/server/async/http_server_async.cpp
// https server: https://live.boost.org/doc/libs/1_74_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

// async model: https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2013/n3747.pdf

const char *ImmutableManagementApis::REQ_PATH_LOGIN = "/login";
const char *ImmutableManagementApis::REQ_PATH_SET = "/set";
const char *ImmutableManagementApis::REQ_PATH_EXTEND = "/extend";
const char *ImmutableManagementApis::REQ_PATH_RENEW = "/renew";
const char *ImmutableManagementApis::REQ_PATH_GET = "/get";
const char *ImmutableManagementApis::REQ_PATH_GETALL = "/getall";

const char *ImmutableManagementApis::REQ_BODY_KEY_FILENAME = "name";
const char *ImmutableManagementApis::REQ_BODY_KEY_POLICY = "policy";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE = "type";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_START_DATE = "start_date";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_DURATION = "duration";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_AUTO_RENEW = "auto_renew";

ImmutableManagementApis::ImmutableManagementApis(
        std::shared_ptr<ImmutableManager> immutableManager
) : _httpServerWorkerCxtPool(16), _immutableManager(immutableManager) {

    //Config &config = Config::getInstance();

    _numWorkerThreads = 4; // TODO take the number of worker threads from configuration

    // ip address and port of the server to bind to
    auto const address = net::ip::make_address("0.0.0.0");
    auto const port = static_cast<unsigned short>(59003);

    // context for ssl certificate
    std::shared_ptr<ssl::context> sslCtx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    bool sslSet = loadServerCertificate(*sslCtx);

    // listen to incoming requests
    _serverThread = std::make_shared<Listener>(
        _httpServerWorkerCxtPool,
        sslSet? sslCtx: nullptr,
        tcp::endpoint{address, port},
        _immutableManager
    );
    _serverThread->run();

    // create the pool of worker threads
    _httpServerWorkerThreads.reserve(_numWorkerThreads);
    for (int i = 0; i < _numWorkerThreads; i++) {
        _httpServerWorkerThreads.emplace_back(
        [this] {
            _httpServerWorkerCxtPool.run();
        });
    }
}

ImmutableManagementApis::~ImmutableManagementApis() {
}

bool ImmutableManagementApis::isLoginRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::put && target == REQ_PATH_LOGIN;
}

bool ImmutableManagementApis::isPolicySetRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_SET;
}

bool ImmutableManagementApis::isPolicyGetRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::get && target == REQ_PATH_GET;
}

bool ImmutableManagementApis::isPolicyGetAllRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::get && target == REQ_PATH_GETALL;
}

bool ImmutableManagementApis::isPolicyExtendRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_EXTEND;
}

bool ImmutableManagementApis::isPolicyRenewRequest(
        const http::verb method,
        const beast::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_RENEW;
}

bool ImmutableManagementApis::checkValidRequestPath(
        const http::verb method,
        const beast::string_view target
) {
    return (
        false
        || isLoginRequest(method, target)
        || isPolicyChangeRequest(method, target)
        || isPolicyInquiryRequest(method, target)
    );
}

bool ImmutableManagementApis::isPolicyChangeRequest(
        const http::verb method,
        const beast::string_view target
) {
    return (
        false
        || isPolicySetRequest(method, target)
        || isPolicyExtendRequest(method, target)
        || isPolicyRenewRequest(method, target)
    );
}

bool ImmutableManagementApis::isPolicyInquiryRequest(
        const http::verb method,
        const beast::string_view target
) {
    return (
        false
        || isPolicyGetRequest(method, target)
        || isPolicyGetAllRequest(method, target)
    );
}

void ImmutableManagementApis::reportFailure(
        beast::error_code ec,
        char const *reason
) {
    LOG(ERROR) << "[Immutable Policy Management API] Failed to " << reason << ", " << ec.message() << ".";
}

bool ImmutableManagementApis::loadServerCertificate(ssl::context &ctx) const {
    //Config &config = Config::getInstance();

    std::string password;
    std::string cert, key, dh;

    // TODO load the certificate, key, and DH parameter file

    if (password.empty() != false) {
        ctx.set_password_callback(
            [password](std::size_t,
                boost::asio::ssl::context_base::password_purpose)
            {
                return password;
            });
    }

    if (cert.empty() || key.empty()) {
        LOG(WARNING) << "No SSL certificate is set for the immutable policy management APIs!";
        return false;
    }

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(
        boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        boost::asio::ssl::context::file_format::pem);

    if (dh.empty() == false) {
        ctx.use_tmp_dh(
            boost::asio::buffer(dh.data(), dh.size()));
    }
    
    return true;
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genGeneralResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const char *key,
        beast::string_view value,
        http::status httpStatus
) {
    http::response<http::string_body> res{httpStatus, req.version()};
    res.set(http::field::content_type, "text/json");
    res.keep_alive(req.keep_alive());
    nlohmann::json bodyJson;
    bodyJson[key] = value;
    res.body() = bodyJson.dump();
    res.prepare_payload();
    return res;
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genRequestSuccessResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
) {
    return genGeneralResponse(req, "result", "success", http::status::ok);
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genRequestFailedResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
) {
    return genGeneralResponse(req, "result", "failed", http::status::ok);
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genBadRequestResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const beast::string_view why
) {
    return genGeneralResponse(req, "error", why, http::status::bad_request);
}

template <class Body, class Allocator, class Send>
    void ImmutableManagementApis::handleNewRequest(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager
) {
    const http::verb &method = req.method();
    beast::string_view target = req.target();

    if (!checkValidRequestPath(method, target)) {
        send(genBadRequestResponse(req, "Illegal request type/path."));
        return;
    }

    //send(echoRequest(req.body()));

    // handle the requests
    if (isLoginRequest(method, target)) {
        handleLogin(req, send, immutableManager);
    } else if (isPolicyChangeRequest(method, target)) {
        handlePolicyChange(req, send, immutableManager);
    } else if (isPolicyInquiryRequest(method, target)) {
        handlePolicyInquiry(req, send, immutableManager);
    } else {
        send(genBadRequestResponse(req, "Illegal request type/path."));
    }
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handleLogin(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager
) {
    return false;
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handlePolicyChange(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager
) {
    const http::verb &method = req.method();
    beast::string_view target = req.target();

    // TODO: authenticate the request issuer

    PolicyApiRequestBody body(static_cast<std::string_view>(req.body()));

    // check for the target file name (essential for all requests)
    if (body.hasObjectName() == false) {
        send(genBadRequestResponse(req, "Missing request parameter (file name)!"));
        return false;
    }

    // get the target file and policy to set/update
    File f;
    std::string name = body.getObjectName();
    f.setName(name.data(), name.size());
    ImmutablePolicy policy = body.getImmutablePolicy();

    if (isPolicySetRequest(method, target)) {
        // set new policy

        // check the required parameters
        if (body.hasFullPolicy() == false) {
            send(genBadRequestResponse(req, "Missing request parameter (all policy attributes)!"));
            return false;
        }

        if (immutableManager->setPolicy(f, policy)) {
            send(genRequestSuccessResponse(req));
            return true;
        }
        send(genRequestFailedResponse(req));
    } else if (isPolicyExtendRequest(method, target)) {
        // extend an existing policy

        // check the required parameters
        if (body.hasFullPolicy() == false) {
            send(genBadRequestResponse(req, "Missing request parameter (all policy attributes)!"));
            return false;
        }

        if (immutableManager->extendPolicy(f, policy)) {
            send(genRequestSuccessResponse(req));
            return true;
        }

        send(genRequestFailedResponse(req));
    } else if (isPolicyRenewRequest(method, target)) {
        // set the auto renew state of an existing policy

        // check the required parameters
        if (body.hasPolicyAutoRenew() == false || body.hasPolicyType() == false) {
            send(genBadRequestResponse(req, "Missing request parameter (policy type or auto renew state)!"));
            return false;
        }

        if (immutableManager->renewPolicy(f, policy)) {
            send(genRequestSuccessResponse(req));
            return true;
        }

        send(genRequestFailedResponse(req));
    }

    return false;
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handlePolicyInquiry(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager
) {
    const http::verb &method = req.method();
    beast::string_view target = req.target();

    // TODO: authenticate the request issuer

    PolicyApiRequestBody body(static_cast<std::string_view>(req.body()));

    // check for the target file name (essential for all requests)
    if (body.hasObjectName() == false) {
        send(genBadRequestResponse(req, "Missing request parameter (file name)!"));
        return false;
    }


    // get the target file and policy to set/update
    File f;
    std::string name = body.getObjectName();
    f.setName(name.data(), name.size());

    if (isPolicyGetRequest(method, target)) {
        if (!body.hasPolicyType()) {
            send(genBadRequestResponse(req, "Missing request parameter (policy type)!"));
            return false;
        }
        ImmutablePolicy policy = body.getImmutablePolicy();
        bool policyExists = immutableManager->getPolicy(f, policy.getType(), policy);
        LOG(INFO) << "Result: " << policyExists << " and " << policy.to_string();
        // TODO send the response
        return true;
    } else if (isPolicyGetAllRequest(method, target)) {
        std::vector<ImmutablePolicy> policies = immutableManager->getAllPolicies(f);
        LOG(INFO) << "Result: " << policies.size() << " policies.";
        for (size_t i = 0; i < policies.size(); i++) {
            LOG(INFO) << "policy [" << i << "] " << policies[i].to_string();
        }
        // TODO send the response
        return true;
    }
    return false;
}

// ImmutableManagementApis;:Listener

ImmutableManagementApis::Listener::Listener(
        net::io_context &ioc,
        std::shared_ptr<ssl::context> ctx,
        tcp::endpoint endpoint,
        std::shared_ptr<ImmutableManager> immutableManager
) : _ioc(ioc) , _ctx(ctx) , _acceptor(ioc), _immutableManager(immutableManager) {
    beast::error_code ec;

    // open the acceptor
    _acceptor.open(endpoint.protocol(), ec);
    if(ec) {
        reportFailure(ec, "open the acceptor for request listening");
    }

    // allow address reuse
    _acceptor.set_option(net::socket_base::reuse_address(true), ec);
    if(ec) {
        reportFailure(ec, "set binding optionsf for request listening");
    }

    // bind to the server address
    _acceptor.bind(endpoint, ec);
    if(ec) {
        reportFailure(ec, "bind the socket for request listening");
    }

    // start listening for connections
    _acceptor.listen(net::socket_base::max_listen_connections, ec);
    if(ec) {
        reportFailure(ec, "start listening to requests");
    }
}

void ImmutableManagementApis::Listener::run() {
    // start accepting incoming connections
    doAccept();
}

void ImmutableManagementApis::Listener::doAccept() {
    // each new connection gets its own strand
    _acceptor.async_accept(
        net::make_strand(_ioc),
        beast::bind_front_handler(
            &Listener::onAccept,
            shared_from_this()));
}

void ImmutableManagementApis::Listener::onAccept(
        beast::error_code ec,
        tcp::socket socket
) {
    if(ec) {
        reportFailure(ec, "accept the client connection");
        return; // to avoid infinite loop
    } else {
        DLOG(INFO) << "Creating a session now " << (_ctx? "with" : "without") << "SSL.";
        // create the Session and run it
        std::make_shared<Session>(
            std::move(socket),
            _ctx,
            _immutableManager
        )->run();
    }

    // accept another connection
    doAccept();
}


// ImmutableManagementApis;:Session

ImmutableManagementApis::Session::SendLambda::SendLambda(Session& self)
    : _self(self) {
}

template<bool isRequest, class Body, class Fields>
void
ImmutableManagementApis::Session::SendLambda::operator() (
        http::message<isRequest, Body,
        Fields>&& msg
) const {
    // The lifetime of the message has to extend
    // for the duration of the async operation so
    // we use a shared_ptr to manage it.
    auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(
        std::move(msg)
    );

    // Store a type-erased version of the shared
    // pointer in the class to keep it alive.
    _self._res = sp;

    // Write the response
    if (_self._sslStream) {
        http::async_write(
            *_self._sslStream,
            *sp,
            beast::bind_front_handler(
                &Session::onWrite,
                _self.shared_from_this(),
                sp->need_eof()));
    } else {
        http::async_write(
            *_self._tcpStream,
            *sp,
            beast::bind_front_handler(
                &Session::onWrite,
                _self.shared_from_this(),
                sp->need_eof()));
    }
}

ImmutableManagementApis::Session::Session(
    tcp::socket&& socket,
    std::shared_ptr<ssl::context> ctx,
    std::shared_ptr<ImmutableManager> immutableManager
) : _sslCtx(ctx), _lambda(*this), _immutableManager(immutableManager)
{
    if (_sslCtx) {
        _sslStream = new net::ssl::stream<beast::tcp_stream>(std::move(socket), *_sslCtx);
    } else {
        _tcpStream = new beast::tcp_stream(std::move(socket));
    }
}

ImmutableManagementApis::Session::~Session() {
    delete _sslStream;
    delete _tcpStream;
}

void ImmutableManagementApis::Session::run() {
    if (_tcpStream == nullptr && _sslStream == nullptr) { return; }
    if (_immutableManager == nullptr) { return; }

    // We need to be executing within a strand to perform async operations
    // on the I/O objects in this Session. Although not strictly necessary
    // for single-threaded contexts, this example code is written to be
    // thread-safe by default.
    net::dispatch(
        _sslStream? _sslStream->get_executor() : _tcpStream->get_executor(),
        beast::bind_front_handler(
            &Session::onRun,
            shared_from_this()));
}

void ImmutableManagementApis::Session::onRun() {
    if (_sslStream) {
        // set the timeout
        beast::get_lowest_layer(*_sslStream).expires_after(
            std::chrono::seconds(30));

        // perform the SSL handshake
        _sslStream->async_handshake(
            ssl::stream_base::server,
            beast::bind_front_handler(
                &Session::onHandShake,
                shared_from_this()));
    } else {
        // directly read the request body for non-SSL requests
        doRead();
    }
}

void ImmutableManagementApis::Session::onHandShake(beast::error_code ec) {
    // check for any SSL handshake error
    if (ec) {
        return reportFailure(ec, "complete handshake with the client");
    }

    // continue to read the request body for non-SSL requests
    doRead();
}

void ImmutableManagementApis::Session::doRead() {
    // make the request empty before reading,
    // otherwise the operation behavior is undefined.
    _req = {};

    // set the timeout.
    beast::tcp_stream &stream =
        _sslStream? beast::get_lowest_layer(*_sslStream) : *_tcpStream
    ;
    stream.expires_after(std::chrono::seconds(timeout));

    if (_sslStream) {
        // read a request
        http::async_read(*_sslStream,
            _buffer,
            _req,
            beast::bind_front_handler(
                &Session::onRead,
                shared_from_this())
        );
    } else {
        // read a request
        http::async_read(*_tcpStream,
            _buffer,
            _req,
            beast::bind_front_handler(
                &Session::onRead,
                shared_from_this())
        );
    }
}

void ImmutableManagementApis::Session::onRead(
        beast::error_code ec,
        std::size_t bytes_transferred
) {
    boost::ignore_unused(bytes_transferred);

    // peer closed the connection
    if (ec == http::error::end_of_stream) {
        return doClose();
    }

    if (ec) {
        return reportFailure(ec, "read the request body");
    }

    // send the response
    handleNewRequest(std::move(_req), _lambda, _immutableManager);
}

void ImmutableManagementApis::Session::onWrite(
    bool keep_alive,
    beast::error_code ec,
    std::size_t bytes_transferred
) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        return reportFailure(ec, "write the response body");
    }

    if (!keep_alive) {
        // This means we should close the connection, usually because
        // the response indicated the "Connection: close" semantic.
        return doClose();
    }

    // Read another request
    doRead();
}

void ImmutableManagementApis::Session::doClose() {
    // set the timeout
    beast::tcp_stream &stream =
        _sslStream? beast::get_lowest_layer(*_sslStream) : *_tcpStream
    ;
    stream.expires_after(std::chrono::seconds(timeout));

    if (_sslStream) {
        // Perform the SSL shutdown
        _sslStream->async_shutdown(
            beast::bind_front_handler(
                &Session::onShutdown,
                shared_from_this()));
    } else {
        beast::error_code ec;
        _tcpStream->socket().shutdown(tcp::socket::shutdown_send, ec);
    }
}

void ImmutableManagementApis::Session::onShutdown(beast::error_code ec) {
}

ImmutableManagementApis::PolicyApiRequestBody::PolicyApiRequestBody(
        std::string_view jsonBody
) {
    try {
        _parsedJson = nlohmann::json::parse(jsonBody);
    } catch (std::exception &e) {
    }
}

ImmutableManagementApis::PolicyApiRequestBody::~PolicyApiRequestBody() {
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasObjectName() const {
    return
        !_parsedJson.is_null()
        && !_parsedJson[REQ_BODY_KEY_FILENAME].is_null()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyType() const {
    return
        !_parsedJson.is_null()
        && !_parsedJson[REQ_BODY_KEY_POLICY].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_TYPE].is_null()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyAutoRenew() const {
    return
        !_parsedJson.is_null()
        && !_parsedJson[REQ_BODY_KEY_POLICY].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_AUTO_RENEW].is_null()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasFullPolicy() const {
    return
        !_parsedJson.is_null()
        && !_parsedJson[REQ_BODY_KEY_POLICY].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_TYPE].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_START_DATE].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_DURATION].is_null()
        && !_parsedJson[REQ_BODY_SUBKEY_POLICY_AUTO_RENEW].is_null()
    ;
}

std::string ImmutableManagementApis::PolicyApiRequestBody::getObjectName() const {
    try {
        return _parsedJson[REQ_BODY_KEY_FILENAME].get<std::string>();
    } catch (std::exception &e) {
    }
    return "";
}

ImmutablePolicy ImmutableManagementApis::PolicyApiRequestBody::getImmutablePolicy() const {
    try {
        ImmutablePolicy policy;

        // set policy type
        auto &type = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_TYPE];
        if (type.is_string()) {
            policy.setType(type.get<std::string>());
        }

        // set policy start date (if available)
        auto &startDate = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_START_DATE];
        if (startDate.is_string()) {
            policy.setStartDate(startDate.get<std::string>());
        }

        // set policy duration (if available)
        auto &duration = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_DURATION];
        if (duration.is_number_unsigned()) {
            policy.setStartDate(duration.get<int>());
        }

        // set policy auto renew
        auto &autoRenew = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_AUTO_RENEW];
        if (autoRenew.is_number_unsigned()) {
            policy.setRenewable(duration.get<int>() > 0);
        }

        return policy;
    } catch (std::exception &e) {
    }
    return ImmutablePolicy(); 
}
