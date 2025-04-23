// SPDX-License-Identifier: Apache-2.0

#include "../../common/config.hh"

#include "./immutable_manager.hh"
#include "./all.hh"

ImmutableManager::ImmutableManager() {
    Config &config = Config::getInstance();
    switch (config.getProxyMetaStoreType()) {
        case MetaStoreType::REDIS:
            _policyStore = new ImmutableRedisPolicyStore();
            break;
        default:
            _policyStore = new ImmutableRedisPolicyStore();
            break;
    }
}

ImmutableManager::~ImmutableManager() {
    delete _policyStore;
}

bool ImmutableManager::setPolicy(const File &f, const ImmutablePolicy &policy) const {
    return _policyStore->setPolicyOnFile(f, policy).success();
}

bool ImmutableManager::getPolicy(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy) const {
    return _policyStore->getPolicyOnFile(f, policy.getType(), policy).success();
}

bool ImmutableManager::extendPolicy(const File &f, const ImmutablePolicy &policy) const {
    return _policyStore->extendPolicyOnFile(f, policy).success();
}

bool ImmutableManager::renewPolicy(const File &f, const ImmutablePolicy &policy) const {
    return _policyStore->renewPolicyOnFile(f, policy.getType(), policy.isRenewable()).success();
}

bool ImmutableManager::deleteAllPolicy(const File &f) const {
    return _policyStore->deleteAllPolicies(f).success();
}

bool ImmutableManager::moveAllPolicy(const File &sf, const File &df) const {
    return _policyStore->moveAllPolicies(sf, df).success();
}

bool ImmutableManager::isImmutable(const File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::IMMUTABLE);
}

bool ImmutableManager::isOnDeleteHold(const File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::DELETION_HOLD);
}

bool ImmutableManager::isOnModificationHold(const File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::MODIFICATION_HOLD);
}

bool ImmutableManager::isOnAccessHold(const File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::ACCESS_HOLD);
}

bool ImmutableManager::isPolicyValid(const File &f, ImmutablePolicy::Type type) const {
    ImmutablePolicy p;
    ImmutablePolicyStore::ActionResult result = _policyStore->getPolicyOnFile(f, type, p);
    return result.success() && !p.isExpired();
}
