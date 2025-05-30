// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_MGT_APIS_AUTH_CLIENT_LDAP_HH__
#define __IMMUTABLE_MGT_APIS_AUTH_CLIENT_LDAP_HH__

#include <ldap.h>

class LdapAuthClient {
public:
    static bool authUser(const std::string user, std::string password);

private:
    LdapAuthClient();
    ~LdapAuthClient();

    static bool initClient(LDAP **ld);
};

#endif // define __IMMUTABLE_MGT_APIS_LDAP_AUTH_CLIENT_HH__
