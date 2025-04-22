// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_MGT_HH__
#define __IMMUTABLE_MGT_HH__

#include <mutex>
#include <string>

#include "../../common/define.hh"
#include "../../ds/immutable_policy.hh"
#include "./immutable_policy_store.hh"

class ImmutableManager {
public:
    ImmutableManager();
    ~ImmutableManager();

    // policy management
    bool setPolicy(const File &f, const ImmutablePolicy &policy) const;
    bool getPolicy(const File &f, ImmutablePolicy::Type type, ImmutablePolicy &policy) const;
    bool extendPolicy(const File &f, const ImmutablePolicy &policy) const;
    bool renewPolicy(const File &f, const ImmutablePolicy &policy) const;
    bool deleteAllPolicy(const File &f) const;

    // TODO cater move (file rename) and copy (file copy)

    // policy checks
    bool isImmutable(const File &f) const;
    bool isOnDeleteHold(const File &f) const;
    bool isOnModificationHold(const File &f) const;
    bool isOnAccessHold(const File &f) const;

private:
    // generic policy check
    bool isPolicyValid(const File &f, ImmutablePolicy::Type type) const;

    ImmutablePolicyStore *_policyStore = nullptr;
};

#endif // define __IMMUTABLE_MGT_HH__
