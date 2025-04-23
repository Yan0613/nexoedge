// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_POLICY_STORE_HH__
#define __IMMUTABLE_POLICY_STORE_HH__

#include "../../ds/file.hh"
#include "../../ds/immutable_policy.hh"

class ImmutablePolicyStore {
public:
    class ActionResult {
    public:
        bool success() const {
            return _success;
        }

        bool _success = false;
        std::string _errorMsg;
    private:
    };

    ImmutablePolicyStore() {}
    virtual ~ImmutablePolicyStore() {}

    /**
     * Attach a new policy to a target file
     *
     * @param[in] f  target file to attach the policy
     * @param[in] policy  target policy to attach
     *
     * @return action results with success set to true if the policy is successfully attached, false otherwise
     **/
    virtual ActionResult setPolicyOnFile(const File &f, const ImmutablePolicy &policy) = 0;

    /**
     * Extend the valid period of an existing policy on a target file
     *
     * @param[in] f  target file with an existing policy to extend
     * @param[in] policy  a policy specifying the type, start date, and new valid period of the existing policy
     *
     * @return action results with success set to true if the policy is successfully extended, false otherwise
     **/
    virtual ActionResult extendPolicyOnFile(const File &f, const ImmutablePolicy &policy) = 0;

    /**
     * Set a new auto-renew status of an existing policy on a target file
     *
     * @param[in] f  target file with an existing policy to update the auto-renew status
     * @param[in] type  target type of the policy to update
     *
     * @return action results with success set to true if the policy is successfully updated, false otherwise
     **/
    virtual ActionResult renewPolicyOnFile(const File &f, const ImmutablePolicy::Type type, bool enable) = 0;

    /**
     * Obtain any existing policy of a target type for a target file
     *
     * @param[in] f  target file to obtain any existing policy of a target type
     * @param[in] type  target type of the policy to obtain
     * @param[out] policy  policy to obtain
     *
     * @return action results with success set to true and the policy set if the policy is obtained, false otherwise
     **/
    virtual ActionResult getPolicyOnFile(const File &f, const ImmutablePolicy::Type type, ImmutablePolicy &policy) = 0;

    /**
     * Obtain all existing policy for a target file
     *
     * @param[in] f  target file to obtain all existing policies
     *
     * @return a list of existing policies attached to the target file
     **/
    virtual std::vector<ImmutablePolicy> getAllPoliciesOnFile(const File &f) = 0;

    /**
     * Delete all policies attached to a target file
     *
     * @param[in] f  target file to remove all attached policies
     *
     * @return true if the target file has no policies (i.e., all policies removed), false otherwise
     **/
    virtual ActionResult deleteAllPolicies(const File &f) = 0;

    /**
     * Migrate all policies attached to a target source file to a target destination file
     *
     * @param[in] sf  target source file to move all attached policies from
     * @param[in] df  target destination file to move all attached policies to
     *
     * @return true if the policies of the target source file are all moved to the target destination file, false otherwise
     **/
    virtual ActionResult moveAllPolicies(const File &sf, const File &df) = 0;

private:
};

#endif // define __IMMUTABLE_POLICY_STORE_HH__
