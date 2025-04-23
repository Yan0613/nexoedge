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

    /**
     * Attach a given policy to the target file
     *
     * @param[in] f        the target file
     * @param[in] policy   policy to attach
     *
     * @return true if the policy is successfully attached, false otherwise
     **/
    bool setPolicy(const File &f, const ImmutablePolicy &policy) const;

    /**
     * Obtain any policy of a given type on the target file
     *
     * @param[in] f        the target file
     * @param[in] type     type of policy to obtain 
     * @param[out] policy  the policy obtained
     *
     * @return true if the policy is successfully obtained, false otherwise
     **/
    bool getPolicy(const File &f, ImmutablePolicy::Type type, ImmutablePolicy &policy) const;
    /**
     * Extend an existing policy on the target file
     *
     * @param[in] f        the target file
     * @param[in] policy   the policy that contains the target type and extended duration to apply
     *
     * @return true if the policy is successfully extended, false otherwise
     **/
    bool extendPolicy(const File &f, const ImmutablePolicy &policy) const;

    /**
     * Update the auto renew state of an existing policy on the target file
     *
     * @param[in] f        the target file
     * @param[in] policy   the policy that contains the target type and new auto renew state to apply
     *
     * @return true if the auto renew state of the policy is successfully updated, false otherwise
     **/
    bool renewPolicy(const File &f, const ImmutablePolicy &policy) const;

    /**
     * Remove all existing policy on the target file
     *
     * @param[in] f        the target file
     *
     * @return true if the file no longer has any policy, false otherwise
     **/
    bool deleteAllPolicy(const File &f) const;

    /**
     * Migrate all existing policy from the target source file to the target destination file
     *
     * @param[in] sf        the target source file
     * @param[in] df        the target destination file
     *
     * @return true if all policies of the source file are migrated, false otherwise
     **/
    bool moveAllPolicy(const File &sf, const File &df) const;

    // policy checks

    /**
     * Check if the target file has a valid immutable policy
     *
     * @param[in] f        the target file
     *
     * @return true if there is a valid immutable policy on the file, false otherwise
     **/
    bool isImmutable(const File &f) const;

    /**
     * Check if the target file has a valid deletion-hold policy
     *
     * @param[in] f        the target file
     *
     * @return true if there is a valid deletion-hold policy on the file, false otherwise
     **/
    bool isOnDeleteHold(const File &f) const;

    /**
     * Check if the target file has a valid modification-hold policy
     *
     * @param[in] f        the target file
     *
     * @return true if there is a valid modification-hold policy on the file, false otherwise
     **/
    bool isOnModificationHold(const File &f) const;

    /**
     * Check if the target file has a valid access-hold policy
     *
     * @param[in] f        the target file
     *
     * @return true if there is a valid access-hold policy on the file, false otherwise
     **/
    bool isOnAccessHold(const File &f) const;

private:

    /**
     * Check if the target file has a valid policy of the target type
     *
     * @param[in] f        the target file
     * @param[in] type     the target policy type
     *
     * @return true if there is a valid policy of the target type on the file, false otherwise
     **/
    bool isPolicyValid(const File &f, ImmutablePolicy::Type type) const;

    ImmutablePolicyStore *_policyStore = nullptr;        /**< immutable policy store */
};

#endif // define __IMMUTABLE_MGT_HH__
