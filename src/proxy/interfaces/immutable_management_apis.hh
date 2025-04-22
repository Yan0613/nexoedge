// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_MGT_APIS_HH__
#define __IMMUTABLE_MGT_APIS_HH__

#include "../immutable/all.hh"

class ImmutableManagementApis {
public:

    ImmutableManagementApis(std::shared_ptr<ImmutableManager> immutableManager);
    ~ImmutableManagementApis();

private:

    //_httpServer;
    //_authStore;
    std::shared_ptr<ImmutableManager> _immutableManager = nullptr;

};

#endif //define __IMMUTABLE_MGT_APIS_HH__
