// SPDX-License-Identifier: Apache-2.0

#include <glog/logging.h>

#include "../../common/config.hh"

#include "immutable_management_apis_auth_client_ldap.hh"


bool LdapAuthClient::authUser(const std::string user, std::string password) {
    LDAP *ld = nullptr;

    // initialize the LDAP connection context
    if (!initClient(&ld)) {
        LOG(ERROR) << "[Immutable Policy Management API (LDAP auth)] Failed to authenticate the user, cannot connected to the server.";
        return false;
    }

    // initialize the LDAP credentials context
    struct berval *cred = ber_bvstrdup(password.c_str());
    struct berval **servercred = nullptr;

    const Config &config = Config::getInstance();

    // construct the LDAP entry distinguish name
    std::string dn;
    std::string ou = config.getProxyLdapUserOrganization();
    std::string dc = config.getProxyLdapDnSuffix();
    dn.append("cn=").append(user);
    if (!ou.empty()) {
        dn.append(",ou=").append(ou);
    }
    if (!dc.empty()) {
        for (size_t i = 0, start = 0; i < dc.size(); i++) {
            bool isDot = dc.at(i) == '.';
            bool isLast = i+1 == dc.size();
            if (isDot || isLast) {
                dn.append(",dc=").append(dc.substr(start, i - start + (isDot? 0 : 1)));
                start = i+1;
            }
        }
    }

    LOG(INFO) << "DN = [" << dn << "] ou = [" << ou << "]";
 
    // try binding the directory (and see if the user can be authenticated)
    int ret = ldap_sasl_bind_s(ld, dn.c_str(), LDAP_SASL_SIMPLE, cred, NULL, NULL, servercred);
    if (ret != 0) {
        LOG(ERROR) << "[Immutable Policy Management API (LDAP auth)] Failed to authenticate the user " << user << ", " << ldap_err2string(ret) << ".";
    }
    // free the LDAP resources
    ber_bvfree(cred);
    ldap_unbind_ext_s(ld, NULL, NULL);

    return ret == 0;
}


bool LdapAuthClient::initClient(LDAP **ld) {
    std::string uri = Config::getInstance().getProxyLdapUri(); //"ldap://localhost:51389";

    LOG(INFO) << "URI = " << uri;

    if (ldap_initialize(ld, uri.c_str()) != LDAP_SUCCESS) {
        *ld = nullptr;
        LOG(ERROR) << "[Immutable Policy Management API (LDAP auth)] Failed to set the LDAP server context.";
        return false;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    return true;
};

