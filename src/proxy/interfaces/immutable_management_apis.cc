// SPDX-License-Identifier: Apache-2.0

#include <fstream>

#include <nlohmann/json.hpp>

#define JWT_DISABLE_PICOJSON
#undef  JWT_DISABLE_BASE64
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include "../../common/config.hh"

#include "./immutable_management_apis.hh"
#include "../../common/util.hh"

#include "./immutable_management_apis_auth_client_ldap.hh"

// http server: https://live.boost.org/doc/libs/1_74_0/libs/beast/example/http/server/async/http_server_async.cpp
// https server: https://live.boost.org/doc/libs/1_74_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

// async model: https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2013/n3747.pdf

const char *RESPONSE_CONTENT_TYPE = "text/json";

const char *ImmutableManagementApis::REQ_PATH_LOGIN = "/login";
const char *ImmutableManagementApis::REQ_PATH_SET = "/set";
const char *ImmutableManagementApis::REQ_PATH_EXTEND = "/extend";
const char *ImmutableManagementApis::REQ_PATH_RENEW = "/renew";
const char *ImmutableManagementApis::REQ_PATH_GET = "/get";
const char *ImmutableManagementApis::REQ_PATH_GETALL = "/getall";

const char *ImmutableManagementApis::REQ_HEADER_TOKEN = "auth_token";
const char *ImmutableManagementApis::REQ_HEADER_USER = "user";

const char *ImmutableManagementApis::REQ_BODY_KEY_USER = REQ_HEADER_USER;
const char *ImmutableManagementApis::REQ_BODY_KEY_PASSWORD = "password";
const char *ImmutableManagementApis::REQ_BODY_KEY_FILENAME = "name";
const char *ImmutableManagementApis::REQ_BODY_KEY_POLICY = "policy";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE = "type";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_START_DATE = "start_date";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_DURATION = "period";
const char *ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_AUTO_RENEW = "auto_renew";

const char *ImmutableManagementApis::REP_BODY_KEY_RESULT = "result";
const char *ImmutableManagementApis::REP_BODY_KEY_ERROR = "error";

const char *ImmutableManagementApis::REP_BODY_VALUE_RESULT_OK = "success";
const char *ImmutableManagementApis::REP_BODY_VALUE_RESULT_FAILED = "failed";

const char *ImmutableManagementApis::AuthTokenGenerator::CLAIM_KEY_USER = "user";
const char *ImmutableManagementApis::AuthTokenGenerator::TOKEN_TYPE = "JWT";
const char *ImmutableManagementApis::AuthTokenGenerator::TOKEN_ISSUER = "nexoedge";
const char *ImmutableManagementApis::AuthTokenGenerator::TOKEN_ID = "immutableMgtApi";

using json = nlohmann::json;

using traits = jwt::traits::nlohmann_json;

static void readFileToString(std::ifstream &inFile, std::string &out) {
    int length, readSize, bufSize = 16 << 10;
    char buf[bufSize];

    // check the size of file, i.e., the total number of bytes to read
    inFile.seekg(0, inFile.end);
    length = inFile.tellg();
    inFile.seekg(0, inFile.beg);
    while (length > 0) {
        // read only up to bufSize
        readSize = std::min(length, bufSize);
        // read the data from the file
        inFile.read(buf, readSize);
        // append the read data to the output string
        out.append(buf, readSize);
        // adjust the reamining number of bytes to read
        length -= readSize;
    }
}

ImmutableManagementApis::ImmutableManagementApis(
        std::shared_ptr<ImmutableManager> immutableManager
) : _httpServerWorkerCxtPool(16), _immutableManager(immutableManager) {

    Config &config = Config::getInstance();

    _numWorkerThreads = config.getProxyImmutableMgtApiNumWorkerThreads();

    // ip address and port of the server to bind to
    const auto address = net::ip::make_address(config.getProxyImmutableMgtApiIP());
    const unsigned short port = config.getProxyImmutableMgtApiPort();

    // context for ssl certificate
    std::shared_ptr<ssl::context> sslCtx = std::make_shared<ssl::context>(ssl::context::tlsv12);
    bool sslSet = loadServerCertificate(*sslCtx);

    // initialize the token generator
    if (config.proxyImmutableMgtApiJWTUseAsymmetric()) {
        std::string publicKey, privateKey;
        std::ifstream inFile;

        // load the private key
        inFile.open(config.getProxyImmutableMgtApiJWTPrivateKey());
        readFileToString(inFile, privateKey);
        inFile.close();

        // load the public key
        inFile.open(config.getProxyImmutableMgtApiJWTPublicKey());
        readFileToString(inFile, publicKey);
        inFile.close();

        // init the token generator
        _tokenGenerator = std::make_shared<AuthTokenGenerator>(privateKey, publicKey);
    } else {
        std::string secretKey;
        std::ifstream inFile;

        // load the secret key
        inFile.open(config.getProxyImmutableMgtApiJWTSecretKey());
        readFileToString(inFile, secretKey);
        inFile.close();

        // init the token generator
        _tokenGenerator = std::make_shared<AuthTokenGenerator>(secretKey);
    }

    // listen to incoming requests
    _serverThread = std::make_shared<Listener>(
        _httpServerWorkerCxtPool,
        sslSet? sslCtx: nullptr,
        tcp::endpoint{address, port},
        _immutableManager,
        _tokenGenerator
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
        const std::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_LOGIN;
}

bool ImmutableManagementApis::isPolicySetRequest(
        const http::verb method,
        const std::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_SET;
}

bool ImmutableManagementApis::isPolicyGetRequest(
        const http::verb method,
        const std::string_view target
) {
    return method == http::verb::get && target == REQ_PATH_GET;
}

bool ImmutableManagementApis::isPolicyGetAllRequest(
        const http::verb method,
        const std::string_view target
) {
    return method == http::verb::get && target == REQ_PATH_GETALL;
}

bool ImmutableManagementApis::isPolicyExtendRequest(
        const http::verb method,
        const std::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_EXTEND;
}

bool ImmutableManagementApis::isPolicyRenewRequest(
        const http::verb method,
        const std::string_view target
) {
    return method == http::verb::post && target == REQ_PATH_RENEW;
}

bool ImmutableManagementApis::checkValidRequestPath(
        const http::verb method,
        const std::string_view target
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
        const std::string_view target
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
        const std::string_view target
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

    std::string password;
    std::string cert, key, dh;

    Config &config = Config::getInstance();
    std::ifstream inFile;
    std::string passwordFilePath = config.getProxyImmutableMgtApiSSLCertPassword();
    std::string certFilePath = config.getProxyImmutableMgtApiSSLCert();
    std::string certKeyFilePath = config.getProxyImmutableMgtApiSSLCertKey();
    std::string dhFilePath = config.getProxyImmutableMgtApiSSLDH();

    // load the certificate password
    if (!passwordFilePath.empty()) {
        inFile.open(passwordFilePath);
        readFileToString(inFile, password);
        inFile.close();
    }

    // load the certificate and key
    if (!certFilePath.empty() && !certKeyFilePath.empty()) {
        inFile.open(certFilePath);
        readFileToString(inFile, cert);
        inFile.close();

        inFile.open(certKeyFilePath);
        readFileToString(inFile, key);
        inFile.close();
    }

    // load any DH parameters
    if (!dhFilePath.empty()) {
        inFile.open(dhFilePath);
        readFileToString(inFile, dh);
        inFile.close();
    }

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
    http::response<http::string_body> ImmutableManagementApis::genEmptyBodyResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        http::status httpStatus
) {
    http::response<http::string_body> res{httpStatus, req.version()};
    res.prepare_payload();
    return res;
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genGeneralResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const char *key,
        std::string_view value,
        http::status httpStatus
) {
    http::response<http::string_body> res{httpStatus, req.version()};
    res.set(http::field::content_type, RESPONSE_CONTENT_TYPE);
    res.keep_alive(req.keep_alive());
    json bodyJson;
    bodyJson[key] = value;
    res.body() = bodyJson.dump();
    res.prepare_payload();
    return res;
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genGeneralResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        json bodyJson,
        http::status httpStatus
) {
    http::response<http::string_body> res{httpStatus, req.version()};
    res.set(http::field::content_type, RESPONSE_CONTENT_TYPE);
    res.keep_alive(req.keep_alive());
    res.body() = bodyJson.dump();
    res.prepare_payload();
    return res;
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genRequestSuccessResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
) {
    return genGeneralResponse(req, REP_BODY_KEY_RESULT, REP_BODY_VALUE_RESULT_OK, http::status::ok);
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genRequestFailedResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
) {
    return genGeneralResponse(req, REP_BODY_KEY_RESULT, REP_BODY_VALUE_RESULT_FAILED, http::status::ok);
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genBadRequestResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const std::string_view why
) {
    return genGeneralResponse(req, REP_BODY_KEY_ERROR, why, http::status::bad_request);
}

template <class Body, class Allocator>
    http::response<http::string_body> ImmutableManagementApis::genUnauthorizedRequestResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
) {
    return genEmptyBodyResponse(req, http::status::unauthorized);
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::authenticateUser(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<AuthTokenGenerator> tokenGenerator 
) {
    // verify the provided token against the provided user
    std::string token (req[REQ_HEADER_TOKEN].begin(), req[REQ_HEADER_TOKEN].end());
    std::string user (req[REQ_HEADER_USER].begin(), req[REQ_HEADER_USER].end());
    if (tokenGenerator->verifyToken(token, user) == false) {
        send(genUnauthorizedRequestResponse(req));
        return false;
    }
    return true;
}

template <class Body, class Allocator, class Send>
    void ImmutableManagementApis::handleNewRequest(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator
) {
    const http::verb &method = req.method();
    std::string target(req.target().begin(), req.target().end());

    // trim the query parameters in the target
    size_t queryStartPos = target.find("?");
    if (queryStartPos != std::string::npos) {
        target = target.substr(0, queryStartPos);
    }

    // check if the requested path is valid
    if (!checkValidRequestPath(method, target)) {
        send(genBadRequestResponse(req, "Illegal request type/path. (1)"));
        return;
    }

    //send(echoRequest(req.body()));

    // handle the requests
    if (isLoginRequest(method, target)) {
        handleLogin(req, send, immutableManager, tokenGenerator);
    } else if (isPolicyChangeRequest(method, target)) {
        handlePolicyChange(req, send, immutableManager, tokenGenerator);
    } else if (isPolicyInquiryRequest(method, target)) {
        handlePolicyInquiry(req, send, immutableManager, tokenGenerator);
    } else {
        send(genBadRequestResponse(req, "Illegal request type/path. (2)"));
    }
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handleLogin(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager,
    std::shared_ptr<AuthTokenGenerator> tokenGenerator 
) {
    PolicyApiRequestBody body(static_cast<std::string_view>(req.body()));
    if (!body.hasUsername() || !body.hasPassword()) {
        send(genBadRequestResponse(req, "Missing login credentials (username, password)."));
        return false;
    }

    // extract the user credentials from the request body
    std::string user = body.getUsername();
    std::string password = body.getPassword();

    if (LdapAuthClient::authUser(user, password)) {
        // return a token upon successful login
        json res;
        res[REQ_HEADER_TOKEN] = tokenGenerator->newToken(user);
        send(genGeneralResponse(req, res, http::status::ok));
        return true;
    }

    // return 401 upon login failure
    json res;
    send(genUnauthorizedRequestResponse(req));
    return false;
}

template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handlePolicyChange(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager,
    std::shared_ptr<AuthTokenGenerator> tokenGenerator 
) {
    const http::verb &method = req.method();
    std::string target(req.target().begin(), req.target().end());

    // authenticate the request issuer
    if (!authenticateUser(req, send, tokenGenerator)) {
        return false;
    }

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
        if (
                body.hasPolicyType() == false
                || body.hasPolicyStartDate() == false
                || body.hasPolicyDuration() == false
        ) {
            send(genBadRequestResponse(req, "Missing request parameter (policy type/start date/period)!"));
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

void ImmutableManagementApis::addPolicyToJson(const ImmutablePolicy &policy, json &json) {
    json[REQ_BODY_SUBKEY_POLICY_TYPE] = policy.getTypeName();
    json[REQ_BODY_SUBKEY_POLICY_START_DATE] = policy.getStartDateString();
    json[REQ_BODY_SUBKEY_POLICY_DURATION] = policy.getDuration();
    json[REQ_BODY_SUBKEY_POLICY_AUTO_RENEW] = policy.isRenewable();
}


template <class Body, class Allocator, class Send> 
bool ImmutableManagementApis::handlePolicyInquiry(
    http::request<Body, http::basic_fields<Allocator>>& req,
    Send &&send,
    std::shared_ptr<ImmutableManager> immutableManager,
    std::shared_ptr<AuthTokenGenerator> tokenGenerator 
) {
    // authenticate the request issuer
    if (!authenticateUser(req, send, tokenGenerator)) {
        return false;
    }

    const http::verb &method = req.method();
    std::string target(req.target().begin(), req.target().end());
    std::string query, filename, policyType;

    // extract the query input parameters
    size_t queryStartPos = target.find("?");
    if (queryStartPos != std::string::npos) {
        query = target.substr(queryStartPos + 1);
        target = target.substr(0, queryStartPos);

        filename = getParameterValue(query, ImmutableManagementApis::REQ_BODY_KEY_FILENAME);
        policyType = getParameterValue(query, ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE);
    }

    // check for the target file name (essential for all requests)
    if (filename.empty()) {
        send(genBadRequestResponse(req, "Missing request parameter (file name)!"));
        return false;
    }

    // get the target file and policy to set/update
    File f;
    f.setName(filename.data(), filename.size());

    if (isPolicyGetRequest(method, target)) {
        if (policyType.empty()) {
            send(genBadRequestResponse(req, "Missing request parameter (policy type)!"));
            return false;
        }
        // fetch the policy if any
        ImmutablePolicy policy;
        policy.setType(policyType);
        bool policyExists = immutableManager->getPolicy(f, policy.getType(), policy);
        // send the response
        json res = json::object();
        if (policyExists) {
            addPolicyToJson(policy, res);
        }
        send(genGeneralResponse(req, res, http::status::ok));
        return true;
    } else if (isPolicyGetAllRequest(method, target)) {
        // fetch all policies if any
        std::vector<ImmutablePolicy> policies = immutableManager->getAllPolicies(f);
        // send the response
        json res = json::array();
        for (size_t i = 0; i < policies.size(); i++) {
            json item;
            addPolicyToJson(policies[i], item); 
            res.push_back(item);
        }
        send(genGeneralResponse(req, res, http::status::ok));
        return true;
    }
    return false;
}

std::string ImmutableManagementApis::getParameterValue(
    const std::string query,
    std::string_view key
) {
    // find the key in the query string
    std::string targetPrefix(key.begin());
    targetPrefix.append("=");
    size_t startPos = query.find(targetPrefix);
    if (startPos == std::string::npos) {
        // return an empty string if the parameter not found
        return "";
    }
    startPos += targetPrefix.size();
    // extract the value
    size_t endPos = query.find("&", startPos);
    return Util::urlDecode(query.substr(startPos, endPos == std::string::npos? endPos : endPos - startPos));
}

// ImmutableManagementApis;:Listener

ImmutableManagementApis::Listener::Listener(
        net::io_context &ioc,
        std::shared_ptr<ssl::context> ctx,
        tcp::endpoint endpoint,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator
) : _ioc(ioc) , _ctx(ctx) , _acceptor(ioc), _immutableManager(immutableManager), _tokenGenerator(tokenGenerator) {
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
        DLOG(INFO) << "Creating a session now " << (_ctx? "with" : "without") << " SSL encryption.";
        // create the Session and run it
        std::make_shared<Session>(
            std::move(socket),
            _ctx,
            _immutableManager,
            _tokenGenerator
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
    std::shared_ptr<ImmutableManager> immutableManager,
    std::shared_ptr<AuthTokenGenerator> tokenGenerator
) : _sslCtx(ctx), _lambda(*this), _immutableManager(immutableManager), _tokenGenerator(tokenGenerator)
{
    if (_sslCtx) {
        // run a session over SSL
        _sslStream = new net::ssl::stream<beast::tcp_stream>(std::move(socket), *_sslCtx);
    } else {
        // run a session over plain-text
        _tcpStream = new beast::tcp_stream(std::move(socket));
    }
    _timeout = Config::getInstance().getProxyImmutableMgtApiSessionTimeoutInSeconds();
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
    stream.expires_after(std::chrono::seconds(_timeout));

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
    handleNewRequest(std::move(_req), _lambda, _immutableManager, _tokenGenerator);
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
    stream.expires_after(std::chrono::seconds(_timeout));

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
        _parsedJson = json::parse(jsonBody);
    } catch (std::exception &e) {
    }
}

ImmutableManagementApis::PolicyApiRequestBody::~PolicyApiRequestBody() {
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasObjectName() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_FILENAME)
        && _parsedJson[REQ_BODY_KEY_FILENAME].is_string()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyType() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_POLICY)
        && _parsedJson[REQ_BODY_KEY_POLICY].is_object()
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_TYPE)
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_TYPE].is_string()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyStartDate() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_POLICY)
        && _parsedJson[REQ_BODY_KEY_POLICY].is_object()
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_START_DATE)
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_START_DATE].is_string()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyDuration() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_POLICY)
        && _parsedJson[REQ_BODY_KEY_POLICY].is_object()
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_DURATION)
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_DURATION].is_number_unsigned()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPolicyAutoRenew() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_POLICY)
        && _parsedJson[REQ_BODY_KEY_POLICY].is_object()
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_AUTO_RENEW)
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_AUTO_RENEW].is_boolean()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasFullPolicy() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_POLICY)
        && _parsedJson[REQ_BODY_KEY_POLICY].is_object()
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_TYPE)
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_START_DATE)
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_DURATION)
        && _parsedJson[REQ_BODY_KEY_POLICY].contains(REQ_BODY_SUBKEY_POLICY_AUTO_RENEW)
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_TYPE].is_string()
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_START_DATE].is_string()
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_DURATION].is_number_unsigned()
        && _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_AUTO_RENEW].is_boolean()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasUsername() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_USER)
        && _parsedJson[REQ_BODY_KEY_USER].is_string()
    ;
}

bool ImmutableManagementApis::PolicyApiRequestBody::hasPassword() const {
    return
        !_parsedJson.is_null()
        && _parsedJson.contains(REQ_BODY_KEY_PASSWORD)
        && _parsedJson[REQ_BODY_KEY_PASSWORD].is_string()
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
    ImmutablePolicy policy;

    // set policy type
    if (hasPolicyType()) {
        auto &type = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_TYPE];
        policy.setType(type.get<std::string>());
    }

    // set policy start date (if available)
    if (hasPolicyStartDate()) {
        auto &startDate = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_START_DATE];
        policy.setStartDate(startDate.get<std::string>());
    }

    // set policy duration (if available)
    if (hasPolicyDuration()) {
        auto &duration = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_DURATION];
        policy.setDuration(duration.get<int>());
    }

    // set policy auto renew
    if (hasPolicyAutoRenew()) {
        auto &autoRenew = _parsedJson[REQ_BODY_KEY_POLICY][REQ_BODY_SUBKEY_POLICY_AUTO_RENEW];
        policy.setRenewable(autoRenew.get<bool>());
    }

    //DLOG(INFO) << "Parsed policy: " << policy.to_string();

    return policy;
}

std::string ImmutableManagementApis::PolicyApiRequestBody::getUsername() const {
    try {
        return _parsedJson[REQ_BODY_KEY_USER].get<std::string>();
    } catch (std::exception &e) {
    }
    return "";
}

std::string ImmutableManagementApis::PolicyApiRequestBody::getPassword() const {
    try {
        return _parsedJson[REQ_BODY_KEY_PASSWORD].get<std::string>();
    } catch (std::exception &e) {
    }
    return "";
}

ImmutableManagementApis::AuthTokenGenerator::AuthTokenGenerator(
        const std::string privateKey,
        const std::string publicKey
) : _privateKey(privateKey), _publicKey(publicKey), _asymmeticSign(true) {
}

ImmutableManagementApis::AuthTokenGenerator::AuthTokenGenerator(
        const std::string key
) : _privateKey(key), _publicKey(""), _asymmeticSign(false) {
}

ImmutableManagementApis::AuthTokenGenerator::~AuthTokenGenerator() {
}

std::string ImmutableManagementApis::AuthTokenGenerator::newToken(
        const std::string &user
) const {
    return newToken(_privateKey, user, _asymmeticSign);
}

std::string ImmutableManagementApis::AuthTokenGenerator::newToken(
        const std::string &privateKey,
        const std::string &user,
        bool asymmetricSign
) {

    // generate a token which expires after an hour
    auto token = jwt::create()
            .set_type(TOKEN_TYPE)
            .set_issuer(TOKEN_ISSUER)
            .set_id(TOKEN_ID)
            .set_issued_now()
            .set_expires_in(std::chrono::seconds{HOUR_IN_SECONDS})
            .set_payload_claim(CLAIM_KEY_USER, jwt::claim(user));
    if (asymmetricSign) {
            return token.sign(jwt::algorithm::rs256("", privateKey, "", ""));
    }
    return token.sign(jwt::algorithm::hs256(privateKey));
}

bool ImmutableManagementApis::AuthTokenGenerator::verifyToken(
        const std::string &token,
        const std::string &expectedUser
) {
    return verifyToken(token, _asymmeticSign? _publicKey : _privateKey, expectedUser, _asymmeticSign);
}

bool ImmutableManagementApis::AuthTokenGenerator::verifyToken(
        const std::string &token,
        const std::string &key,
        const std::string &expectedUser,
        bool asymmetricSign
) {
    try {
        // decode the base64 token
        const auto decoded = jwt::decode(token);
        // verify the signature for the expected user claim and expiration date
        auto verifier = jwt::verify()
            .with_issuer(TOKEN_ISSUER)
            .with_claim(CLAIM_KEY_USER, jwt::claim(expectedUser));
        if (asymmetricSign) {
            verifier.allow_algorithm(jwt::algorithm::rs256(key, "", "", ""));
        } else {
            verifier.allow_algorithm(jwt::algorithm::hs256(key));
        }
        verifier.verify(decoded);
    } catch (std::exception &e) {
        LOG(INFO) << "Failed to verify the token for user " << expectedUser << ", " << e.what() << ".";
        return false;
    }
    return true;
}
