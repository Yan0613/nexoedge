// SPDX-License-Identifier: Apache-2.0

#include <cstdlib>

#include <glog/logging.h>

#include "./immutable_policy_store_redis.hh"

using ActionResult = ImmutablePolicyStore::ActionResult;

ImmutableRedisPolicyStore::ImmutableRedisPolicyStore() : RedisMetaStore() {
}

ImmutableRedisPolicyStore::~ImmutableRedisPolicyStore() {
}

ActionResult ImmutableRedisPolicyStore::setPolicyOnFile(const File &f, const ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    const ImmutablePolicy::Type policyType = policy.getType();

    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" to set the policy");
        LOG(ERROR) << result._errorMsg;
        return result;
    }

    size_t numOps = 0;

    redisReply *r = NULL;
    // avoid concurrent modification to the policy
    r = (redisReply*) redisCommand(
        _cxt
        , "WATCH %b"
        , policyKey, keyLength
    );

    if (r == NULL || (r->type != REDIS_REPLY_STRING && r->type != REDIS_REPLY_STATUS) || strncmp(r->str, "OK", r->len) != 0) {
        result._errorMsg
                .append("Failed to watch the policy key of the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" to set the policy")
                .append(" (reply type = ")
                .append(std::to_string(policyType))
                .append(")")
        ;
        LOG(ERROR) << result._errorMsg;
        if (r == NULL) { reconnect(); }
        freeReplyObject(r);
        return result;
    }

    freeReplyObject(r);

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

    // assume the transaction is successful first and check for any error
    result._success = true;

    // get the policy-set transaction results
    for (size_t i = 0; i < numOps; i++) {
        if (redisGetReply(_cxt, (void**) &r) != REDIS_OK || r->type == REDIS_REPLY_ERROR) {
            result._success = false;
            result._errorMsg
                    .append("Failed to get a reply (request ")
                    .append(std::to_string(i+1))
                    .append(") on setting the ")
                    .append(ImmutablePolicy::TypeString[policyType])
                    .append(" policy of file ")
                    .append(f.name);
            LOG(ERROR) << result._errorMsg;
        } else if (i + 1 == numOps) {
            // check for the expected requests at the end of the transaction
            if (r->elements != numOps - 2) {
                result._success = false;
                result._errorMsg
                        .append("Failed to get all replies on setting the ")
                        .append(ImmutablePolicy::TypeString[policyType])
                        .append(" policy of file ")
                        .append(f.name);
                LOG(ERROR) << result._errorMsg;
            }
            // check for any request failure
            for (size_t j = 0; j < r->elements; j++) {
                const int type = r->element[j]->type;
                const int res = r->element[j]->integer;
                if (type != REDIS_REPLY_INTEGER || res != 1) {
                    result._success = false;
                    result._errorMsg
                            .append("Failed to set the ")
                            .append(ImmutablePolicy::TypeString[policyType])
                            .append(" policy of file ")
                            .append(f.name);
                    LOG(ERROR) << result._errorMsg << " (reply type = " << type << " res = " << res << ")";
                    break;
                }
            }
        }
        freeReplyObject(r);
    }

    return result;
}

ActionResult ImmutableRedisPolicyStore::extendPolicyOnFile(const File &f, const ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    const ImmutablePolicy::Type policyType = policy.getType();
    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        result._success = false;
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" to extend the policy.");
        LOG(ERROR) << result._errorMsg;
    }

    std::string script = " \
        local d=redis.call('hget', KEYS[1], KEYS[2]); \
        if (d and tonumber(ARGV[1]) > tonumber(d)) then \
            local res=redis.call('hset', KEYS[1], KEYS[2], ARGV[1]); \
            if (res and tonumber(res) == 0) then \
                return 1; \
            else \
                return 0; \
            end \
        end \
        return 0; \
    ";

    redisReply *r = (redisReply*) redisCommand(
        _cxt
        , "EVAL %s 2 %b %s %d"
        , script.c_str()
        , policyKey, keyLength
        , policyFieldDuration
        , policy.getDuration()
    );
    if (r == NULL) {
        result._success = false;
        result._errorMsg
                .append("Failed to extend the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to policy store connection error.");
    } else if (r->type != REDIS_REPLY_INTEGER || r->integer != 1) {
        result._success = false;
        result._errorMsg
                .append("Failed to extend the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" (reply type = ")
                .append(std::to_string(r->type))
                .append(" integer = ")
                .append(std::to_string(r->integer))
                .append(")");
        LOG(ERROR) << result._errorMsg;
    } else {
        result._success = true;
        LOG(INFO) << "Extended the " << ImmutablePolicy::TypeString[policyType] << " policy of file " << f.name;
    }

    return result;
}

ActionResult ImmutableRedisPolicyStore::renewPolicyOnFile(const File &f, const ImmutablePolicy &policy, bool enable) {
    std::lock_guard<std::mutex> lk(_lock);

    const ImmutablePolicy::Type policyType = policy.getType();
    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, policy.getType(), policyKey);
    if (keyLength == 0) {
        result._success = false;
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" to auto renew the policy.");
        LOG(ERROR) << result._errorMsg;
    }

    // TODO

    return result;
}

ActionResult ImmutableRedisPolicyStore::getPolicyOnFile(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    return getPolicyOnFile_(f, type, policy);
}

std::vector<ImmutablePolicy> ImmutableRedisPolicyStore::getAllPoliciesOnFile(const File &f) {
    std::lock_guard<std::mutex> lk(_lock);

    std::vector<ImmutablePolicy> policyList;

    // go through all possible types of policy
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ImmutablePolicy policy;
        if (!getPolicyOnFile_(f, static_cast<ImmutablePolicy::Type>(policyType), policy).success()) { continue; }
        policyList.push_back(policy);
    }

    return policyList;
}

ActionResult ImmutableRedisPolicyStore::deleteAllPolicies(const File &f) {
    std::lock_guard<std::mutex> lk(_lock);

    // go through all possible types of policy
    ActionResult finalResult;
    finalResult._success = true;
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ActionResult result = deletePolicyOnFile_(f, static_cast<ImmutablePolicy::Type>(policyType));
        if (!result.success()) { finalResult = result; }
    }

    return finalResult;

}

int ImmutableRedisPolicyStore::genFilePolicyKey(const File &f, const ImmutablePolicy::Type type, char *policyKey) {
    if (policyKey == NULL) { return 0; }

    // decide the id for the policy
    const char *policyId = "u";
    switch (type) {
    case ImmutablePolicy::Type::IMMUTABLE:
        policyId = "i";
        break;
    case ImmutablePolicy::Type::MODIFICATION_HOLD:
        policyId = "m";
        break;
    case ImmutablePolicy::Type::DELETION_HOLD:
        policyId = "d";
        break;
    case ImmutablePolicy::Type::ACCESS_HOLD:
        policyId = "r";
        break;
    default:
        LOG(ERROR) << "Cannot identify the type of policy to set (type = " << ImmutablePolicy::TypeString[type] << ")";
        return 0;
        break;
    }

    // construct the key
    char fileKey[PATH_MAX];
    int keyLength = genFileKey(f.namespaceId, f.name, f.nameLength, fileKey);
    fileKey[keyLength] = '\0';
    return snprintf(policyKey, PATH_MAX, "/ip-%s_%s", policyId, fileKey);
}

ActionResult ImmutableRedisPolicyStore::getPolicyOnFile_(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy) {
    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, type, policyKey);
    if (keyLength == 0) {
        result._success = false;
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" poicy for file ")
                .append(f.name)
                .append(" to retrieve the policy.");
        LOG(ERROR) << result._errorMsg;
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
        result._errorMsg
                .append("Failed to obtain the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to policy store connection error.");
        LOG(ERROR) << result._errorMsg;
        reconnect();
        return result;
    }
    if (r->type != REDIS_REPLY_ARRAY || r->elements < expectedNumFields) {
        result._success = false;
        result._errorMsg
                .append("Failed to get policy of file ")
                .append(f.name)
                .append(" due to invalid policy store response, type = ")
                .append(std::to_string(r->type))
                .append(", elements = ")
                .append(std::to_string(r->elements));
        LOG(ERROR) << result._errorMsg;
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
        LOG(INFO) << "Try obtaining a non-existing " << ImmutablePolicy::TypeString[type] << " policy of file " << f.name << ".";
        return result;
    }

    char *end = nullptr;

    // set the policy start date
    if (r->element[0]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg
                .append("Failed to obtain the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to unexpected policy store response on the start date, type = ")
                .append(std::to_string(r->element[0]->type));
        LOG(ERROR) << result._errorMsg;
        return result;
    }
    end = r->element[0]->str + r->element[0]->len;
    policy.setStartDate(std::strtoul(r->element[0]->str, &end, 10));

    // set the policy valid period
    if (r->element[1]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg
                .append("Failed to obtain the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to unexpected policy store response on the valid period, type = ")
                .append(std::to_string(r->element[1]->type));
        LOG(ERROR) << result._errorMsg;
        return result;
    }
    end = r->element[1]->str + r->element[1]->len;
    policy.setDuration(std::strtoul(r->element[1]->str, &end, 10));

    // set the auto renew status
    if (r->element[2]->type != REDIS_REPLY_STRING) {
        result._success = false;
        result._errorMsg
                .append("Failed to obtain the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to unexpected policy store response on the auto renew status, type = ")
                .append(std::to_string(r->element[2]->type));
        LOG(ERROR) << result._errorMsg;
        return result;
    }
    policy.setRenewable(strncmp(r->element[2]->str, "0", 1) != 0);

    // set policy type
    policy.setType(type);

    // mark the operation as successful
    result._success = true;
    
    LOG(INFO) << "Obtained the " << ImmutablePolicy::TypeString[type] << " policy of file " << f.name << ".";

    return result;
}

ActionResult ImmutableRedisPolicyStore::deletePolicyOnFile_(const File &f, const ImmutablePolicy::Type type) {
    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, type, policyKey);
    if (keyLength == 0) {
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" to delete the policy");
        LOG(ERROR) << result._errorMsg;
        return result;
    }

    redisReply *r = NULL;
    // avoid concurrent modification to the policy
    r = (redisReply*) redisCommand(
        _cxt
        , "DEL %b"
        , policyKey, keyLength
    );

    if (r == NULL || r->type != REDIS_REPLY_INTEGER || r->integer < 0 || r->integer >= 2) {
        result._errorMsg
                .append("Failed to watch the policy key of the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" to delete the policy");
        LOG(ERROR) << result._errorMsg;
        if (r == NULL) { reconnect(); }
        freeReplyObject(r);
        return result;
    }

    freeReplyObject(r);

    result._success = true;

    LOG(INFO) << "Deleted the " << ImmutablePolicy::TypeString[type] << " policy of file " << f.name;

    return result;
}
