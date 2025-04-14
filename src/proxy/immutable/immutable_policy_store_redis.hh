// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_POLICY_STORE_REDIS_HH__
#define __IMMUTABLE_POLICY_STORE_REDIS_HH__

#include <mutex>

#include <hiredis/hiredis.h>
#include <hiredis/hiredis_ssl.h>

#include "./immutable_policy_store.hh"
#include "../metastore/redis_metastore.hh"

class ImmutableRedisPolicyStore : public ImmutablePolicyStore, private RedisMetaStore {
public:
    ImmutableRedisPolicyStore();
    ~ImmutableRedisPolicyStore();

    /**
     * See ImmutablePolicyStore::setPolicyOnFile()
     **/
    ActionResult setPolicyOnFile(const File &f, const ImmutablePolicy &policy);

    /**
     * See ImmutablePolicyStore::extendPolicyOnFile()
     **/
    ActionResult extendPolicyOnFile(const File &f, const ImmutablePolicy &policy);

    /**
     * See ImmutablePolicyStore::renewPolicyOnFile()
     **/
    ActionResult renewPolicyOnFile(const File &f, const ImmutablePolicy &policy, bool enable);

    /**
     * See ImmutablePolicyStore::getPolicyOnFile()
     **/
    ActionResult getPolicyOnFile(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy);

    /**
     * See ImmutablePolicyStore::getAllPoliciesOnFile()
     **/
    std::vector<ImmutablePolicy> getAllPoliciesOnFile(const File &f);

    /**
     * See ImmutablePolicyStore::deleteAllPolicies()
     **/
    ActionResult deleteAllPolicies(const File &f);

private:

    /**
     * Internal function to obtain and parse the policy from the policy store
     *
     * @param[in] f  target file to obtain any existing policy of a target type
     * @param[in] type  target type of the policy to obtain
     * @param[out] policy  policy to obtain
     *
     * @return action results with success set to true and the policy set if the policy is successfully attached, false otherwise
     **/
    ActionResult getPolicyOnFile_(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy);

    ActionResult deletePolicyOnFile_(const File &f, const ImmutablePolicy::Type type);

    /**
     * Generate the file and type specific policy key of the policy in the policy store
     *
     * @param[in] f  target file to obtain any existing policy of a target type
     * @param[in] type  target type of the policy to obtain
     * @param[out] policyKey  a char array of size PATH_MAX for storing the generated policy key 
     *
     * @return length of the generated policy key successful, 0 otherwise
     **/
    int genFilePolicyKey(const File &f, const ImmutablePolicy::Type type, char *policyKey);

    const char *policyFieldType = "t";
    const char *policyFieldStartDate = "s";
    const char *policyFieldDuration = "d";
    const char *policyFieldAutoRenew = "r";
};

#endif // define __IMMUTABLE_POLICY_STORE_REDIS_HH__
