// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_MGT_APIS_HH__
#define __IMMUTABLE_MGT_APIS_HH__

#include <vector>

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

class ImmutableManagementApis {
public:

    ImmutableManagementApis(std::shared_ptr<ImmutableManager> immutableManager);
    ~ImmutableManagementApis();

protected:

    // forward declaration
    class Session;
    class Listener;

private:

    static bool isLoginRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicySetRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicyGetRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicyGetAllRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicyExtendRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicyRenewRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool checkValidRequestPath(
        const http::verb method,
        const beast::string_view target
    );

    static bool isPolicyChangeRequest(
        const http::verb method,
        const beast::string_view target
    );
    static bool isPolicyInquiryRequest(
        const http::verb method,
        const beast::string_view target
    );

    static void reportFailure(beast::error_code ec, char const *reason);

    template <class Body, class Allocator>
    static http::response<http::string_body> genGeneralResponse(
        http::request<Body, http::basic_fields<Allocator>>& req,
        const char *key,
        beast::string_view value,
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
            const beast::string_view why
    );

    template <class Body, class Allocator, class Send> 
    static void handleNewRequest(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager
    );

    template <class Body, class Allocator, class Send> 
    static bool handleLogin(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager
    );

    template <class Body, class Allocator, class Send> 
    static bool handlePolicyChange(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager
    );

    template <class Body, class Allocator, class Send> 
    static bool handlePolicyInquiry(
        http::request<Body, http::basic_fields<Allocator>>& req,
        Send &&send,
        std::shared_ptr<ImmutableManager> immutableManager
    );

    bool loadServerCertificate(ssl::context &ctx) const;

    // request path/target definitions
    static const char *REQ_PATH_LOGIN;
    static const char *REQ_PATH_SET;
    static const char *REQ_PATH_EXTEND;
    static const char *REQ_PATH_RENEW;
    static const char *REQ_PATH_GET;
    static const char *REQ_PATH_GETALL;

    static const char *REQ_BODY_KEY_FILENAME;
    static const char *REQ_BODY_KEY_POLICY;
    static const char *REQ_BODY_SUBKEY_POLICY_TYPE;
    static const char *REQ_BODY_SUBKEY_POLICY_START_DATE;
    static const char *REQ_BODY_SUBKEY_POLICY_DURATION;
    static const char *REQ_BODY_SUBKEY_POLICY_AUTO_RENEW;

    // server listening and worker threads
    const int MAX_SERVER_THREADS = 1024;
    int _numWorkerThreads = 1;

    std::shared_ptr<Listener> _serverThread = nullptr;
    net::io_context _httpServerWorkerCxtPool;
    std::vector<std::thread> _httpServerWorkerThreads;

    //_authStore;
    std::shared_ptr<ImmutableManager> _immutableManager = nullptr;

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
            std::shared_ptr<ImmutableManager> immutableManager
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

    };

    // Accepts incoming connections and launches the Sessions
    class Listener : public std::enable_shared_from_this<Listener>
    {
    public:
        Listener(
            net::io_context &ioc,
            std::shared_ptr<ssl::context> ctx,
            tcp::endpoint endpoint,
            std::shared_ptr<ImmutableManager> immutableManager
        );

        void run();

    private:
        void doAccept();
        void onAccept(beast::error_code ec, tcp::socket socket);

        net::io_context &_ioc;
        std::shared_ptr<ssl::context> _ctx = nullptr;
        tcp::acceptor _acceptor;
        std::shared_ptr<ImmutableManager> _immutableManager = nullptr;
    };

    class PolicyApiRequestBody {
    public:
        PolicyApiRequestBody(std::string_view jsonBody);
        ~PolicyApiRequestBody();

        std::string getObjectName() const;
        ImmutablePolicy getImmutablePolicy() const;

        bool hasPolicyType() const;
        bool hasPolicyAutoRenew() const;
        bool hasFullPolicy() const;
        bool hasObjectName() const;

    private:
        nlohmann::json _parsedJson;
    };

};

#endif //define __IMMUTABLE_MGT_APIS_HH__
