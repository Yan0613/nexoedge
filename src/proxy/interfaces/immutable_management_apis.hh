// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_MGT_APIS_HH__
#define __IMMUTABLE_MGT_APIS_HH__

#include <vector>
#include <string>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>

#include "../immutable/all.hh"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

using json = nlohmann::json;

class ImmutableManagementApis {
public:

    ImmutableManagementApis(std::shared_ptr<ImmutableManager> immutableManager);
    ~ImmutableManagementApis();

    static void addPolicyToJson(const ImmutablePolicy &policy, json &json);

    // request path/target definitions
    static const char *REQ_PATH_LOGIN;
    static const char *REQ_PATH_SET;
    static const char *REQ_PATH_EXTEND;
    static const char *REQ_PATH_RENEW;
    static const char *REQ_PATH_GET;
    static const char *REQ_PATH_GETALL;

    // request header keys
    static const char *REQ_HEADER_TOKEN;
    static const char *REQ_HEADER_USER;

    // request body keys
    static const char *REQ_BODY_KEY_FILENAME;
    static const char *REQ_BODY_KEY_POLICY;
    static const char *REQ_BODY_KEY_USER;
    static const char *REQ_BODY_KEY_PASSWORD;
    static const char *REQ_BODY_SUBKEY_POLICY_TYPE;
    static const char *REQ_BODY_SUBKEY_POLICY_START_DATE;
    static const char *REQ_BODY_SUBKEY_POLICY_DURATION;
    static const char *REQ_BODY_SUBKEY_POLICY_AUTO_RENEW;

    // response body keys and values
    static const char *REP_BODY_KEY_RESULT;
    static const char *REP_BODY_KEY_ERROR;
    static const char *REP_BODY_VALUE_RESULT_OK;
    static const char *REP_BODY_VALUE_RESULT_FAILED;


protected:

    // forward declaration
    class Session;
    class Listener;
    class AuthTokenGenerator;

private:

    static bool isLoginRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool isPolicySetRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool isPolicyGetRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool isPolicyGetAllRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool isPolicyExtendRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool isPolicyRenewRequest(
        const http::verb method,
        const std::string_view target
    );
    static bool checkValidRequestPath(
        const http::verb method,
        const std::string_view target
    );

    static bool isPolicyChangeRequest(
        const http::verb method,
        const std::string_view target
    );

    static bool isPolicyInquiryRequest(
        const http::verb method,
        const std::string_view target
    );

    static void reportFailure(beast::error_code ec, char const *reason);

    template <class Body, class Allocator>
    static http::response<http::string_body> genEmptyBodyResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        http::status httpStatus
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genGeneralResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const char *key,
        std::string_view value,
        http::status httpStatus
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genGeneralResponse(
            http::request<Body, http::basic_fields<Allocator>>& req,
            json bodyJson,
            http::status httpStatus
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genRequestSuccessResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genRequestFailedResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genBadRequestResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
            const std::string_view why
    );

    template <class Body, class Allocator>
    static http::response<http::string_body> genUnathorizedRequestResponse(
        http::request<Body, http::basic_fields<Allocator>>& req
    );

    template <class Body, class Allocator, class Send> 
    static bool authenticateUser(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator 
    );

    template <class Body, class Allocator, class Send> 
    static void handleNewRequest(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator
    );

    template <class Body, class Allocator, class Send> 
    static bool handleLogin(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator 
    );

    template <class Body, class Allocator, class Send> 
    static bool handlePolicyChange(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator 
    );

    template <class Body, class Allocator, class Send> 
    static bool handlePolicyInquiry(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager,
        std::shared_ptr<AuthTokenGenerator> tokenGenerator 
    );

    static std::string getParameterValue(
        std::string query,
        std::string_view key
    );

    bool loadServerCertificate(ssl::context &ctx) const;

    // server listening and worker threads
    const int MAX_SERVER_THREADS = 1024;
    int _numWorkerThreads = 1;

    std::shared_ptr<Listener> _serverThread = nullptr;
    net::io_context _httpServerWorkerCxtPool;
    std::vector<std::thread> _httpServerWorkerThreads;

    //_authStore;
    std::shared_ptr<ImmutableManager> _immutableManager = nullptr;
    std::shared_ptr<AuthTokenGenerator> _tokenGenerator = nullptr;

protected:

    // Handles an HTTP server connection
    class Session : public std::enable_shared_from_this<Session> {
    public:
        // a generic lambda function object is used to send an HTTP message.
        class SendLambda {
        public:
            explicit SendLambda(Session& self);

            template<bool isRequest, class Body, class Fields>
            void
            operator()(http::message<isRequest, Body, Fields>&& msg) const;

        private:
            Session& _self;

        };

        explicit Session(
            tcp::socket&& socket,
            std::shared_ptr<ssl::context> ctx,
            std::shared_ptr<ImmutableManager> immutableManager,
            std::shared_ptr<AuthTokenGenerator> tokenGenerator
        );
        ~Session();

        // start the asynchronous operation
        void run();

        void onRun();
        void onHandShake(beast::error_code ec);
        void onRead(
            beast::error_code ec,
            std::size_t bytes_transferred);
        void onWrite(
            bool keep_alive,
            beast::error_code ec,
            std::size_t bytes_transferred);
        void onShutdown(beast::error_code ec);

        void doRead();
        void doClose();

    private:

        const int timeout = 60;

        net::ssl::stream<beast::tcp_stream> *_sslStream = nullptr;  /*<< stream for SSL connection */
        beast::tcp_stream *_tcpStream = nullptr;                    /*<< stream for non-SSL connection */

        std::shared_ptr<ssl::context> _sslCtx = nullptr;            /*<< context for SSL (e.g., cert and key) */

        beast::flat_buffer _buffer;
        http::request<http::string_body> _req;
        std::shared_ptr<void> _res;
        SendLambda _lambda;
        std::shared_ptr<ImmutableManager> _immutableManager = nullptr;
        std::shared_ptr<AuthTokenGenerator> _tokenGenerator = nullptr;

    };

    // Accepts incoming connections and launches the Sessions
    class Listener : public std::enable_shared_from_this<Listener>
    {
    public:
        Listener(
            net::io_context &ioc,
            std::shared_ptr<ssl::context> ctx,
            tcp::endpoint endpoint,
            std::shared_ptr<ImmutableManager> immutableManager,
            std::shared_ptr<AuthTokenGenerator> tokenGenerator
        );

        void run();

    private:
        void doAccept();
        void onAccept(beast::error_code ec, tcp::socket socket);

        net::io_context &_ioc;
        std::shared_ptr<ssl::context> _ctx = nullptr;
        tcp::acceptor _acceptor;
        std::shared_ptr<ImmutableManager> _immutableManager = nullptr;
        std::shared_ptr<AuthTokenGenerator> _tokenGenerator = nullptr;
    };

    class PolicyApiRequestBody {
    public:
        PolicyApiRequestBody(std::string_view jsonBody);
        ~PolicyApiRequestBody();

        std::string getObjectName() const;
        ImmutablePolicy getImmutablePolicy() const;
        std::string getUsername() const;
        std::string getPassword() const;

        bool hasPolicyType() const;
        bool hasPolicyStartDate() const;
        bool hasPolicyDuration() const;
        bool hasPolicyAutoRenew() const;
        bool hasFullPolicy() const;
        bool hasObjectName() const;
        bool hasUsername() const;
        bool hasPassword() const;

    private:
        json _parsedJson;
    };

    class AuthTokenGenerator {
    public:
        AuthTokenGenerator(
            const std::string privateKey,
            const std::string publicKey
        );
        AuthTokenGenerator(
            const std::string key
        );
        ~AuthTokenGenerator();

        static std::string newToken(
            const std::string &privateKey,
            const std::string &user,
            bool asymmetricSign
        );
        std::string newToken(const std::string &user) const;

        static bool verifyToken(
            const std::string &token,
            const std::string &key,
            const std::string &expectedUser,
            bool asymmetricSign
        );
        bool verifyToken(const std::string &token, const std::string &expectedUser); 

        static const char *CLAIM_KEY_USER;

    private:
        std::string _privateKey;
        std::string _publicKey;
        bool _asymmeticSign = false;

        static const char *TOKEN_TYPE;
        static const char *TOKEN_ISSUER;
        static const char *TOKEN_ID;
    };
};

#endif //define __IMMUTABLE_MGT_APIS_HH__
