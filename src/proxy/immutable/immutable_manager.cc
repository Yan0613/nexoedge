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

bool ImmutableManager::setPolicy(File &f, const ImmutablePolicy &policy) const {
    initFileNamespaceId(f);
    return _policyStore->setPolicyOnFile(f, policy).success();
}

bool ImmutableManager::getPolicy(File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy) const {
    initFileNamespaceId(f);
    return _policyStore->getPolicyOnFile(f, policy.getType(), policy).success();
}

std::vector<ImmutablePolicy> ImmutableManager::getAllPolicies(File &f) const {
    initFileNamespaceId(f);
    return _policyStore->getAllPoliciesOnFile(f);
}

bool ImmutableManager::extendPolicy(File &f, const ImmutablePolicy &policy) const {
    initFileNamespaceId(f);
    return _policyStore->extendPolicyOnFile(f, policy).success();
}

bool ImmutableManager::renewPolicy(File &f, const ImmutablePolicy &policy) const {
    initFileNamespaceId(f);
    return _policyStore->renewPolicyOnFile(f, policy.getType(), policy.isRenewable()).success();
}

bool ImmutableManager::deleteAllPolicy(File &f) const {
    initFileNamespaceId(f);
    return _policyStore->deleteAllPolicies(f).success();
}

bool ImmutableManager::moveAllPolicy(File &sf, File &df) const {
    initFileNamespaceId(sf);
    initFileNamespaceId(df);
    return _policyStore->moveAllPolicies(sf, df).success();
}

bool ImmutableManager::isImmutable(File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::IMMUTABLE);
}

bool ImmutableManager::isOnDeleteHold(File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::DELETION_HOLD);
}

bool ImmutableManager::isOnModificationHold(File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::MODIFICATION_HOLD);
}

bool ImmutableManager::isOnAccessHold(File &f) const {
    return isPolicyValid(f, ImmutablePolicy::Type::ACCESS_HOLD);
}

bool ImmutableManager::isPolicyValid(File &f, ImmutablePolicy::Type type) const {
    ImmutablePolicy p;
    initFileNamespaceId(f);
    ImmutablePolicyStore::ActionResult result = _policyStore->getPolicyOnFile(f, type, p);
    return result.success() && !p.isExpired();
}

bool ImmutableManager::initFileNamespaceId(File &f) const {
    if (f.namespaceId == INVALID_NAMESPACE_ID) {
        f.namespaceId = Config::getInstance().getProxyNamespaceId();
    }
    return false;
}
