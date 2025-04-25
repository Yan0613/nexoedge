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

    // ensure the policy covers the time now
    if (!policy.isStarted() || policy.isExpired()) {
        result._success = false;
        result._errorMsg
                .append("Failed to proceed with the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to invalid policy (")
                .append(policy.isStarted()? "started" : "not started")
                .append(", ")
                .append(policy.isExpired()? "is expired" : "not expired")
                .append(")")
        ;
        LOG(ERROR) << result._errorMsg;
        return result;
    }

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
                .append(" to set the policy");
        LOG(ERROR) << result._errorMsg;
        return result;
    }

    std::string script = " \
        local p = redis.call('hmget', KEYS[1], ARGV[1], ARGV[2]); \
        local policyNotExists = not p[1] and not p[2]; \
        local policyHasExpired = true; \
        if (p[1] and p[2]) then \
            local policyEndTime = tonumber(p[1]) + tonumber(p[2]) * 86400; \
            local now = tonumber(ARGV[7]); \
            if (policyEndTime > now) then \
                policyHasExpired = false; \
            end \
        end \
        if (policyNotExists or policyHasExpired) then \
            local res=redis.call('hmset', KEYS[1], ARGV[1], ARGV[4], ARGV[2], ARGV[5], ARGV[3], ARGV[6]); \
            if (res) then \
                return 0; \
            end \
            return 1; \
        end \
        return 2; \
    ";

    time_t timeNow;
    time(&timeNow);

    redisReply *r = (redisReply*) redisCommand(
        _cxt
        , "EVAL %s 1 %b %s %s %s %i %i %s %i"
        , script.c_str()
        , policyKey, keyLength
        , policyFieldStartDate
        , policyFieldDuration
        , policyFieldAutoRenew
        , policy.getStartDate()
        , policy.getDuration()
        , policy.isRenewable()? "1" : "0"
        , timeNow
    );

    if (r == NULL) {
        // the policy store is not responding
        result._success = false;
        result._errorMsg
                .append("Failed to set the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to policy store connection error.");
        reconnect();
    } else if (r->type != REDIS_REPLY_INTEGER || r->integer != 0) {
        // the policy extension failed
        result._success = false;
        result._errorMsg
                .append("Failed to set the ")
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
        // the policy extension is successful
        result._success = true;
        LOG(INFO) << "Set the " << ImmutablePolicy::TypeString[policyType] << " policy of file " << f.name;
    }

    return result;
}

ActionResult ImmutableRedisPolicyStore::extendPolicyOnFile(const File &f, const ImmutablePolicy &policy) {
    std::lock_guard<std::mutex> lk(_lock);

    const ImmutablePolicy::Type policyType = policy.getType();
    ActionResult result;

    // ensure the policy covers the time now
    if (!policy.isStarted() || policy.isExpired()) {
        result._success = false;
        result._errorMsg
                .append("Failed to proceed with the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to invalid policy (")
                .append("started = ")
                .append(std::to_string(policy.isStarted()))
                .append("; expired = ")
                .append(std::to_string(policy.isExpired()))
                .append(")")
        ;
        LOG(ERROR) << result._errorMsg;
        return result;
    }

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

    // script inputs
    // KEYS[1]: policy key
    // ARGV[1]: field name for valid period
    // ARGV[2]: new valid period
    // the script does the following:
    // 1. Get the current start date and valid period.
    // 2. If the policy does not exist (d is nil), then do nothing.
    // 3. If the user-input new end date extends the existing one, update to the new start date and valid period.
    // 4. Otherwise, do nothing.
    // the script returns 0 on a successful extension,
    //                    1 on an unsuccessful extension attempt,
    //                    2 if the user-provided new end date is not an extension,
    //                    3 if the policy does not exist
    std::string script = " \
        local p = redis.call('hmget', KEYS[1], ARGV[1], ARGV[2]); \
        if (p[1] and p[2]) then \
            local newEndTime = tonumber(ARGV[3]) + tonumber(ARGV[4]) * 86400; \
            local oldEndTime = tonumber(p[1]) + tonumber(p[2]) * 86400; \
            if (newEndTime > oldEndTime) then \
                local res=redis.call('hmset', KEYS[1], ARGV[1], ARGV[3], ARGV[2], ARGV[4]); \
                if (res) then \
                    return 0; \
                else \
                    return 1; \
                end \
            end \
            return 2; \
        end \
        return 3; \
    ";

    redisReply *r = (redisReply*) redisCommand(
        _cxt
        , "EVAL %s 1 %b %s %s %i %i"
        , script.c_str()
        , policyKey, keyLength
        , policyFieldStartDate
        , policyFieldDuration
        , policy.getStartDate()
        , policy.getDuration()
    );

    if (r == NULL) {
        // the policy store is not responding
        result._success = false;
        result._errorMsg
                .append("Failed to extend the ")
                .append(ImmutablePolicy::TypeString[policyType])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to policy store connection error.");
        reconnect();
    } else if (r->type != REDIS_REPLY_INTEGER || r->integer != 0) {
        // the policy extension failed
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
        // the policy extension is successful
        result._success = true;
        LOG(INFO) << "Extended the " << ImmutablePolicy::TypeString[policyType] << " policy of file " << f.name;
    }

    return result;
}

ActionResult ImmutableRedisPolicyStore::renewPolicyOnFile(const File &f, const ImmutablePolicy::Type type, bool enable) {
    std::lock_guard<std::mutex> lk(_lock);

    ActionResult result;

    // generate the policy key for the file
    char policyKey[PATH_MAX];
    int keyLength = genFilePolicyKey(f, type, policyKey);
    if (keyLength == 0) {
        result._success = false;
        result._errorMsg
                .append("Failed to generate the policy key of the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" to auto renew the policy.");
        LOG(ERROR) << result._errorMsg;
    }
    
    // script inputs
    // KEYS[1]: policy key
    // ARGV[1]: field name for start date
    // ARGV[2]: field name for valid period
    // ARGV[3]: field name for auto renew state
    // ARGV[4]: time now
    // ARGV[5]: new auto renew state to set
    // the script does the following:
    // 1. Get the current start date, valid period, and auto renew state of the target policy.
    // 2. If the policy does not exist (p[1] or p[2] or p[3] is nil), then do nothing.
    // 3. If the user-input new renew state is to enable auto renew,
    //    a. If the policy has not expired, set the auto renew state to enabled for the policy.
    //    a. Otherwise, do nothing.
    // 4. If the user-input new renew state is to disable auto renew, update the valid period to the current 'time window' and the new state to the policy.
    // the script returns 0 on a successful auto renew state update,
    //                    1 on an unsuccessful update attempt,
    //                    2 if the policy does not exist
    std::string script = " \
        local p = redis.call('hmget', KEYS[1], ARGV[1], ARGV[2], ARGV[3]); \
        if (p[1] and p[2] and p[3]) then \
            if (tonumber(ARGV[4]) == 1) then \
                local res=redis.call('hset', KEYS[1], ARGV[3], ARGV[5]); \
                if (res and tonumber(res) == 0) then \
                    return 0; \
                end \
                return 1; \
            end \
            local st = tonumber(p[1]); \
            local d = tonumber(p[2]); \
            local now = tonumber(ARGV[4]); \
            while (now >= st + d * 86400) do \
                st = st + d * 86400; \
            end \
            local res=redis.call('hmset', KEYS[1], ARGV[1], st, ARGV[2], d, ARGV[3], ARGV[5]); \
            if (res) then \
                return 0; \
            end \
            return 1; \
        end \
        return 2; \
    ";

    time_t timeNow;
    time(&timeNow);

    redisReply *r = (redisReply*) redisCommand(
        _cxt
        , "EVAL %s 1 %b %s %s %s %i %i"
        , script.c_str()
        , policyKey, keyLength
        , policyFieldStartDate
        , policyFieldDuration
        , policyFieldAutoRenew
        , timeNow
        , enable
    );

    // check the update result
    if (r == NULL) {
        // the policy store is not responding
        result._success = false;
        result._errorMsg
                .append("Failed to update the auto renew status of the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" due to policy store connection error.");
        reconnect();
    } else if (r->type != REDIS_REPLY_INTEGER || r->integer != 0) {
        // the policy extension failed
        result._success = false;
        result._errorMsg
                .append("Failed to update the auto renew status fo the ")
                .append(ImmutablePolicy::TypeString[type])
                .append(" policy of file ")
                .append(f.name)
                .append(" (reply type = ")
                .append(std::to_string(r->type))
                .append(" integer = ")
                .append(std::to_string(r->integer))
                .append(")");
        LOG(ERROR) << result._errorMsg;
    } else {
        // the policy extension is successful
        result._success = true;
        LOG(INFO) << "Updated the auto renew state of " << ImmutablePolicy::TypeString[type] << " policy of file " << f.name << " to " << (enable? "enabled" : "disabled");
    }

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

ActionResult ImmutableRedisPolicyStore::moveAllPolicies(const File &sf, const File &df) {
    std::lock_guard<std::mutex> lk(_lock);

    size_t numOps = 0;

    // start a transaction
    redisAppendCommand(
        _cxt
        , "MULTI"
    );
    numOps++;

    // go through all possible types of policy; append the migration instruction
    ActionResult finalResult;
    finalResult._success = true;
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ImmutablePolicy::Type type = static_cast<ImmutablePolicy::Type>(policyType);
        char oldPolicyKey[PATH_MAX], newPolicyKey[PATH_MAX];
        int oldKeyLength = genFilePolicyKey(sf, type, oldPolicyKey);
        int newKeyLength = genFilePolicyKey(df, type, newPolicyKey);
        redisAppendCommand(
            _cxt
            , "RENAME %b %b"
            , oldPolicyKey, oldKeyLength
            , newPolicyKey, newKeyLength
        );
        numOps++;
    }

    // end of the transaction
    redisAppendCommand(
        _cxt
        , "EXEC"
    );
    numOps++;


    // assume the transaction is successful first and check for any error
    ImmutablePolicyStore::ActionResult result;
    result._success = true;
    redisReply *r = nullptr;

    // get the policy-set transaction results
    for (size_t i = 0; i < numOps; i++) {
        if (redisGetReply(_cxt, (void**) &r) != REDIS_OK || r->type == REDIS_REPLY_ERROR) {
            // the policy store is not connecting or responding an error
            result._success = false;
            result._errorMsg
                    .append("Failed to get a reply (request ")
                    .append(std::to_string(i+1))
                    .append(") on moving the policies of file ")
                    .append(sf.name);
            LOG(ERROR) << result._errorMsg;
            if (r == NULL) { reconnect(); }
        } else if (i + 1 == numOps) {
            // check for the expected responses at the end of the transaction
            if (r->elements != numOps - 2) {
                result._success = false;
                result._errorMsg
                        .append("Failed to get all replies on moving the policies of file")
                        .append(sf.name);
                LOG(ERROR) << result._errorMsg;
            }
            // check for any request failure
            for (size_t j = 0; j < r->elements; j++) {
                const int type = r->element[j]->type;
                const char *msg = r->element[j]->str;
                const int msgLength = r->element[j]->len;
                if (type != REDIS_REPLY_STRING
                        && type != REDIS_REPLY_ERROR
                        && type != REDIS_REPLY_STATUS
                        && strncmp(msg, "OK", msgLength) != 0
                ) {
                    result._success = false;
                    result._errorMsg
                            .append("Failed to move the ")
                            .append(ImmutablePolicy::TypeString[j])
                            .append(" policy of file ")
                            .append(sf.name);
                    LOG(ERROR) << result._errorMsg << " (reply type = " << type << ", msg = " << msg << ")";
                    break;
                }
            }
        }
        freeReplyObject(r);
    }

    return result;
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
        result._success = false;
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
