// SPDX-License-Identifier: Apache-2.0

#include <cstdlib>

#include <glog/logging.h>

#include "./immutable_policy_store_redis.hh"

using ImmutablePolicyType = ImmutablePolicy::ImmutablePolicyType;
using ImmutablePolicyStoreActionResult = ImmutablePolicyStore::ImmutablePolicyStoreActionResult;

ImmutableRedisPolicyStore::ImmutableRedisPolicyStore() : RedisMetaStore() {
}

ImmutableRedisPolicyStore::~ImmutableRedisPolicyStore() {
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::setPolicyOnFile(const File &f, const ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        LOG(ERROR) << "Failed to generate the policy key of policy type = " << (int) policy.getType() << " for file " << f.name;
        return ImmutablePolicyStoreActionResult();
    }

    int numOps = 0;

    // set the policy
    // start the transaction
    redisAppendCommand(
        _cxt
        , "MULTI"
    );
    numOps++;
    // add the fields
    redisAppendCommand(
        _cxt
        , "HSETNX %b %s %i"
        , policyKey, keyLength
        , policyFieldStartDate
        , policy.getStartDate()
    );
    numOps++;
    redisAppendCommand(
        _cxt
        , "HSETNX %b %s %i"
        , policyKey, keyLength
        , policyFieldDuration
        , policy.getDuration()
    );
    numOps++;
    redisAppendCommand(
        _cxt
        , "HSETNX %b %s %s"
        , policyKey, keyLength
        , policyFieldAutoRenew
        , policy.isRenewable()? "1" : "0"
    );
    numOps++;
    // end the transaction
    redisAppendCommand(
        _cxt
        , "EXEC"
    );
    numOps++;

    ImmutablePolicyStoreActionResult result;
    result._success = true;

    // get the results
    redisReply *r = NULL;
    for (int i = 0; i < numOps; i++) {
        if (redisGetReply(_cxt, (void**) &r) != REDIS_OK) {
            LOG(ERROR) << "Failed to get a reply for request " << (i+1) << " for setting the policy of type = " << (int) policy.getType() << " for file " << f.name;
            result._success = false;
            result._errorMsg = "Failed to get a successful response from the policy store.";
        }
    }

    return result;
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::extendPolicyOnFile(const File &f, const ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    ImmutablePolicyStoreActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        LOG(ERROR) << "Failed to generate the policy key of policy type = " << (int) policy.getType() << " for file " << f.name;
        result._success = false;
        result._errorMsg = "Failed to generate the policy key for policy retrieval.";
    }

    // TODO

    return result;
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::renewPolicyOnFile(const File &f, const ImmutablePolicy &policy, bool enable) {
    std::lock_guard<std::mutex> lk(_lock);

    ImmutablePolicyStoreActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        LOG(ERROR) << "Failed to generate the policy key of policy type = " << (int) policy.getType() << " for file " << f.name;
        result._success = false;
        result._errorMsg = "Failed to generate the policy key for policy retrieval.";
    }

    // TODO

    return result;
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::getPolicyOnFile(const File &f, const ImmutablePolicy::ImmutablePolicyType type, ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    return getPolicyOnFile_(f, type, policy);
}

std::vector<ImmutablePolicy> ImmutableRedisPolicyStore::getAllPoliciesOnFile(const File &f) {
    std::lock_guard<std::mutex> lk(_lock);

    std::vector<ImmutablePolicy> policyList;

    // go through all possible types of policy
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicyType::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ImmutablePolicy policy;
        if (!getPolicyOnFile_(f, static_cast<ImmutablePolicyType>(policyType), policy).success()) { continue; }
        policyList.push_back(policy);
    }

    return policyList;
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::deleteAllPolicies(const File &f) {
    std::lock_guard<std::mutex> lk(_lock);

    // go through all possible types of policy
    ImmutablePolicyStoreActionResult finalResult;
    finalResult._success = true;
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicyType::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ImmutablePolicyStoreActionResult result = deletePolicyOnFile_(f, static_cast<ImmutablePolicyType>(policyType));
        if (result.success()) {
            LOG(INFO) << "Deleted the policy of type = " << policyType << " for file " << f.name;
        } else {
            LOG(INFO) << "Failed to delete the policy of type = " << policyType << " for file " << f.name;
            finalResult = result;
        }
    }

    return finalResult;

}

int ImmutableRedisPolicyStore::genFilePolicyKey(const File &f, const ImmutablePolicyType type, char *policyKey) {
    if (policyKey == NULL) { return 0; }

    // decide the id for the policy
    const char *policyId = "u";
    switch (type) {
    case ImmutablePolicyType::IMMUTABLE:
        policyId = "i";
        break;
    case ImmutablePolicyType::MODIFICATION_HOLD:
        policyId = "m";
        break;
    case ImmutablePolicyType::DELETION_HOLD:
        policyId = "d";
        break;
    case ImmutablePolicyType::ACCESS_HOLD:
        policyId = "r";
        break;
    default:
        LOG(ERROR) << "Cannot identify the type of policy to set (type = " << (int) type;
        return 0;
        break;
    }

    // construct the key
    char fileKey[PATH_MAX];
    int keyLength = genFileKey(f.namespaceId, f.name, f.nameLength, fileKey);
    fileKey[keyLength] = '\0';
    return snprintf(policyKey, PATH_MAX, "/ip-%s_%s", policyId, fileKey);
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::getPolicyOnFile_(const File &f, const ImmutablePolicy::ImmutablePolicyType type, ImmutablePolicy &policy) {
    ImmutablePolicyStoreActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, type, policyKey);
    if (keyLength == 0) {
        LOG(ERROR) << "Failed to generate the policy key of policy type = " << (int) policy.getType() << " for file " << f.name;
        result._success = false;
        result._errorMsg = "Failed to generate the policy key for policy retrieval.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to policy key generation error";
        return result;
    }

    // retrieve the policy fields
    redisReply *r = (redisReply*) redisCommand(
        _cxt
        , "HMGET %b %s %s %s"
        , policyKey, keyLength
        , policyFieldStartDate
        , policyFieldDuration
        , policyFieldAutoRenew
    );

    const int expectedNumFields = 3;

    // check for an expected valid response from the policy store
    if (r == NULL) {
        result._success = false;
        result._errorMsg = "Unexpected error when connecting the policy store.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to policy store connection error.";
        reconnect();
        return result;
    }
    if (r->type != REDIS_REPLY_ARRAY || r->elements < expectedNumFields) {
        result._success = false;
        result._errorMsg = "Unexpected response from the policy store.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to invalid policy store response, type = " << r->type << ", elements = " << (int) r->elements;
        return result;
    }

    // if the policy does not exists, all fields should be 'nil' in the policy store response
    if (
        r->element[0]->type == REDIS_REPLY_NIL
        && r->element[1]->type == REDIS_REPLY_NIL
        && r->element[2]->type == REDIS_REPLY_NIL
    ) {
        result._success = true;
        result._errorMsg = "Policy not exists.";
        LOG(INFO) << "Try obtaining a non-existing policy of type " << (int) type << " for file " << f.name << ".";
        return result;
    }
    
    LOG(INFO) << "Obtained the policy of type " << (int) type << " for file " << f.name << ".";

    char *end = nullptr;

    // set the policy start date
    if (r->element[0]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg = "Unexpected response from the policy store.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to unexpected policy store response, type = " << r->element[0]->type;
        return result;
    }
    end = r->element[0]->str + r->element[0]->len;
    policy.setStartDate(std::strtoul(r->element[0]->str, &end, 10));

    // set the policy valid period
    if (r->element[1]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg = "Unexpected response from the policy store.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to unexpected policy store response, type = " << r->element[1]->type;
        return result;
    }
    end = r->element[0]->str + r->element[0]->len;
    policy.setDuration(std::strtoul(r->element[1]->str, &end, 10));

    // set the auto renew status
    if (r->element[2]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg = "Unexpected response from the policy store.";
        LOG(ERROR) << "Failed to get policy of file " << f.name << " due to unexpected policy store response, type = " << r->element[2]->type;
        return result;
    }
    policy.setRenewable(strncmp(r->element[2]->str, "0", 1) != 0);

    // set policy type
    policy.setType(type);

    // mark the operation as successful
    result._success = true;

    return result;
}

ImmutablePolicyStoreActionResult ImmutableRedisPolicyStore::deletePolicyOnFile_(const File &f, const ImmutablePolicy::ImmutablePolicyType type) {
    return ImmutablePolicyStoreActionResult();
}
