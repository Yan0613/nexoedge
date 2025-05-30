// SPDX-License-Identifier: Apache-2.0

#ifndef __UTIL_HH__
#define __UTIL_HH__

#include <set>
#include <string>

#include <zmq.hpp>

#include "config.hh"

class Util {
public:
    /**
     * Whether the message is sent from a proxy
     *
     * @param[in] message direction
     * @return true if the message is sent from a proxy, false otherwise
     **/
    static inline bool isMsgFromProxy(MessageDirection direction) {
        return direction == PROXY_TO_AGENT;
    }

    /**
     * Whether the message is sent from an agent
     *
     * @param[in] message direction
     * @return true if the message is sent from an agent, false otherwise
     **/
    static inline bool isMsgFromAgent(MessageDirection direction) {
        return direction == AGENT_TO_AGENT || direction == AGENT_TO_PROXY;
    }

    /**
     * Whether the message is sending to an agent
     *
     * @param[in] message direction
     * @return true if the message is sending to an agent, false otherwise
     **/
    static inline bool isMsgToAgent(MessageDirection direction) {
        return direction == AGENT_TO_AGENT || direction == PROXY_TO_AGENT;
    }

    /**
     * Whether the message is sending to a proxy
     *
     * @param[in] message direction
     * @return true if the message is sending to a proxy, false otherwise
     **/
    static inline bool isMsgToProxy(MessageDirection direction) {
        return direction == AGENT_TO_PROXY;
    }

    /**
     * Set socket options according to configuration
     *
     * @param[in, out] socket socket to set the options
     * @param[in] message direction 
     * @param[in] whether the socket is a server listening socket
     **/
    static void setSocketOptions(zmq::socket_t *socket, MessageDirection direction, bool isServer = false) {
        Config &config = Config::getInstance();
        
        int bufferSize = config.getTcpBufferSize();
        socket->setsockopt(ZMQ_SNDBUF, bufferSize);
        socket->setsockopt(ZMQ_RCVBUF, bufferSize);

        if (socket == 0)
            return;

        if (config.manualTcpKeepAlive()) {
            socket->setsockopt(ZMQ_TCP_KEEPALIVE, 1);
            socket->setsockopt(ZMQ_TCP_KEEPALIVE_IDLE, config.getTcpKeepAliveIdle());
            socket->setsockopt(ZMQ_TCP_KEEPALIVE_INTVL, config.getTcpKeepAliveIntv());
            socket->setsockopt(ZMQ_TCP_KEEPALIVE_CNT, config.getTcpKeepAliveCnt());
        }

        if (config.useCurve()) {
            const int curveKeySize = 41;
            // whether the socket is for a listening server 
            socket->setsockopt(ZMQ_CURVE_SERVER, isServer? 1 : 0);
            bool isFromProxy = isMsgFromProxy(direction);
            bool isToProxy= isMsgToProxy(direction);
            // the public and secret keys for secure connections
            if (!isServer) {
                const char *remotePublicKey = isToProxy? config.getProxyCurvePublicKey() : config.getAgentCurvePublicKey();
                const char *localPublicKey = isFromProxy? config.getProxyCurvePublicKey() : config.getAgentCurvePublicKey();
                socket->setsockopt(ZMQ_CURVE_SERVERKEY, remotePublicKey, curveKeySize);
                socket->setsockopt(ZMQ_CURVE_PUBLICKEY, localPublicKey, curveKeySize);
            }
            const char *localSecretKey = isFromProxy? config.getProxyCurveSecretKey() : config.getAgentCurveSecretKey();
            socket->setsockopt(ZMQ_CURVE_SECRETKEY, localSecretKey, curveKeySize);
        }
    }

    static bool includeSample(int population, double samplingRate) {
        return rand() % (int)(population * 1e3) <= samplingRate * (population * 1e3);
    } 

    /**
     * URL encode an input string
     *
     * @param[in] src string to encode
     * @return encoded string
     **/
    static std::string urlEncode(const std::string &src) {
        const std::map<char, const char *> urlCharsToEncodeMap = {
            { ' ', "%20" },
            { '!', "%21" },
            { '"', "%22" },
            { '#', "%23" },
            { '$', "%24" },
            { '%', "%25" },
            { '&', "%26" },
            { '\'', "%27" },
            { '(', "%28" },
            { ')', "%29" },
            { '*', "%2A" },
            { '+', "%2B" },
            { ',', "%2C" },
            { '-', "%2D" },
            { '.', "%2E" },
            { '/', "%2F" },
            { ':', "%3A" },
            { ';', "%3B" },
            { '<', "%3C" },
            { '=', "%3D" },
            { '>', "%3E" },
            { '?', "%3F" },
            { '@', "%40" },
            { '[', "%5B" },
            { '\\', "%5C" },
            { ']', "%5D" },
            { '^', "%5E" },
            { '_', "%5F" },
            { '`', "%60" },
            { '{', "%7B" },
            { '|', "%7C" },
            { '}', "%7D" },
            { '~', "%7E" },
            // TODO support the pound and euro dollar signs
        };

        std::string encoded;
        encoded.reserve(src.size());
        for (auto it = src.begin(); it != src.end(); it++) {
            if (urlCharsToEncodeMap.count(*it) > 0) {
                encoded.append(urlCharsToEncodeMap.at(*it));
            } else {
                encoded.append(1, *it);
            }
        }
        return encoded;
    }

    /**
     * URL decode an input string
     *
     * @param[in] src string to decode
     * @return decoded string
     **/
    static std::string urlDecode(const std::string &src) {
        const std::map<std::string, char> urlCharsToDecodeMap = {
            { "%20" , ' ' },
            { "%21" , '!' },
            { "%22" , '"' },
            { "%23" , '#' },
            { "%24" , '$' },
            { "%25" , '%' },
            { "%26" , '&' },
            { "%27" , '\'' },
            { "%28" , '(' },
            { "%29" , ')' },
            { "%2A" , '*' },
            { "%2B" , '+' },
            { "%2C" , ',' },
            { "%2D" , '-' },
            { "%2E" , '.' },
            { "%2F" , '/' },
            { "%3A" , ':' },
            { "%3B" , ';' },
            { "%3C" , '<' },
            { "%3D" , '=' },
            { "%3E" , '>' },
            { "%3F" , '?' },
            { "%40" , '@' },
            { "%5B" , '[' },
            { "%5C" , '\\' },
            { "%5D" , ']' },
            { "%5E" , '^' },
            { "%5F" , '_' },
            { "%60" , '`' },
            { "%7B" , '{' },
            { "%7C" , '|' },
            { "%7D" , '}' },
            { "%7E" , '~' },
            // TODO support the pound and euro dollar signs
        };

        std::string decoded;
        decoded.reserve(src.size());
        for (size_t i = 0; i < src.size(); i++) {
            if (src[i] == '%' && i + 3 <= src.size()) {
                std::string key = src.substr(i, 3);
                if (urlCharsToDecodeMap.count(key) > 0) {
                    decoded.append(1, urlCharsToDecodeMap.at(key));
                }
                i += 2;
            } else {
                decoded.append(1, src[i]);
            }
        }
        return decoded;
    }
};

#endif //define __UTIL_HH__
