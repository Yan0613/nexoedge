// SPDX-License-Identifier: Apache-2.0

#ifndef __IMMUTABLE_POLICY_HH__
#define __IMMUTABLE_POLICY_HH__

#include <ctime>
#include <string>

class ImmutablePolicy {
public:
    ImmutablePolicy();
    ~ImmutablePolicy();

    // definitions - policy type
    enum Type {
        IMMUTABLE,
        MODIFICATION_HOLD,
        DELETION_HOLD,
        ACCESS_HOLD,

        UNKNOWN_IMMUTABLE_POLICY
    };

    static const char *TypeString[UNKNOWN_IMMUTABLE_POLICY + 1];

    bool operator== (const ImmutablePolicy &rhs) {
        return 
            _type == rhs._type
            && _start == rhs._start
            && _duration == rhs._duration
            && _autoRenew == rhs._autoRenew
        ;
    }

    bool operator!= (const ImmutablePolicy &rhs) {
        return 
            _type != rhs._type
            || _start != rhs._start
            || _duration != rhs._duration
            || _autoRenew != rhs._autoRenew
        ;
    }

    // type
    /**
     * Set the type of the policy
     *
     * @param[in] type  type of the policy
     *
     * @return if the new type of the policy is set
     **/
    bool setType(const Type type);
    /**
     * Obtain the type of the policy
     *
     * @return the type of the policy
     **/
    Type getType() const;

    // start time
    /**
     * Set the start date of the policy (the start date is always rounded to 00:00:00UTC on the same day) 
     *
     * @param[in] startDate  start date of the policy in UTC time
     *
     * @return if the new start date of the policy is set
     **/
    bool setStartDate(const time_t startDate);

    /**
     * Obtain the start date of the policy
     *
     * @return the start date of the policy in seconds from UTC
     **/
    time_t getStartDate() const;

    /**
     * Obtain the start date of the policy
     *
     * @return the start date of the policy in UTC time and RFC 7231 (format "Www, dd Mmm yyyy HH:mm:ss GMT")
     **/
    std::string getStartDateString() const;

    // policy duration
    /**
     * Set the duration of the policy
     *
     * @param[in] days  the new duration of the policy in number of days
     *
     * @return if the new duration of the policy is set
     **/
    bool setDuration(const unsigned short days);

    /**
     * Check the duration of the policy
     *
     * @return the number of days that the policy last
     **/
    unsigned short getDuration() const;

    // end time
    /**
     * Obtain the end date of the policy
     *
     * @return the end date of the policy in seconds from UTC
     **/
    time_t getEndDate() const;

    /**
     * Obtain the end date of the policy
     *
     * @return the end date of the policy in UTC timeand RFC 7231 (format "Www, dd Mmm yyyy HH:mm:ss GMT")
     **/
    std::string getEndDateString() const;

    // renewable
    /**
     * Update the renewable state of the policy
     *
     * @param[in] renewable  true to set the policy as renewable, false otherwise
     *
     * @return true if the state is updated; false otherwise.
     **/
    bool setRenewable(const bool renewable);

    /**
     * Check the renewable state of the policy
     *
     * @return true if the policy is renewable, false otherwise.
     **/
    bool isRenewable() const;

    // whether the policy is defined
    /**
     * Check if the policy is defined (all fields are properly set)
     *
     * @return true if the policy is defined
     **/
    bool isDefined() const;

    /**
     * Check if the policy has expired
     *
     * @return true if the policy has expired
     **/
    bool isExpired() const;

    // comparison between policies
    /**
     * Check if this policy extends another (i.e., policy of the same time with a later expiration date)
     *
     * @param[in] target  target policy to compare for extension
     *
     * @return true if this policy extend the target policy, false otherwise
     **/
    bool isExtension(const ImmutablePolicy &target) const;

private:

    /**
     * Reset all fields of the policy
     **/
    void reset();

    time_t convertStartDateToUTC(const struct tm &t) const;
    std::string convertTimeToRFC7231(const struct tm &t) const;

    // internal fields of a policy
    Type _type = UNKNOWN_IMMUTABLE_POLICY;  /**< type of the policy */
    time_t _start = 0;                                     /**< starting time of the policy */
    short _duration = 0;                                   /**< duration of the policy (in days) */
    bool _autoRenew = false;                               /**< whether the policy auto renews */
};

#endif // define __IMMUTABLE_POLICY_HH__
