// SPDX-License-Identifier: Apache-2.0

#include "../common/define.hh"
#include "./immutable_policy.hh"

using ImmutablePolicyType = ImmutablePolicy::ImmutablePolicyType;

// convert the time from time_t to struct tm
bool convertTimet2Tm(const time_t tt, struct tm &tm) {
    return gmtime_r(&tt, &tm) != nullptr;
}

ImmutablePolicy::ImmutablePolicy() {
    reset();
}

ImmutablePolicy::~ImmutablePolicy() {
    reset();
}

bool ImmutablePolicy::setType(const ImmutablePolicyType type) {
    _type = type;
    return true;
}

ImmutablePolicyType ImmutablePolicy::getType() const {
    return _type;
}

bool ImmutablePolicy::setStartDate(const time_t startDate) {
    struct tm newStartDate;

    // convert the time format
    if (!convertTimet2Tm(startDate, newStartDate)) { return false; }

    // set the time to 00:00:00UTC of the day
    newStartDate.tm_sec = 0;
    newStartDate.tm_min = 0;
    newStartDate.tm_hour = 0;

    // set the new policy start date
    _start = convertStartDateToUTC(newStartDate);
    return true;
}

time_t ImmutablePolicy::getStartDate() const {
    return _start;
}

std::string ImmutablePolicy::getStartDateString() const {
    struct tm date;
    if (!convertTimet2Tm(_start, date)) { return ""; }
    return convertTimeToRFC7231(date);
}

bool ImmutablePolicy::setDuration(const unsigned short days) {
    _duration = days;
    return true;
}

unsigned short ImmutablePolicy::getDuration() const {
    return _duration;
}

time_t ImmutablePolicy::getEndDate() const {
    return _start + DAY_IN_SECONDS * _duration;
}

std::string ImmutablePolicy::getEndDateString() const {
    struct tm date;
    if (!convertTimet2Tm(getEndDate(), date)) { return ""; }
    return convertTimeToRFC7231(date);
}

bool ImmutablePolicy::setRenewable(const bool renewable) {
    _autoRenew = renewable;
    return true;
}

bool ImmutablePolicy::isRenewable() const {
    return _autoRenew;
}

bool ImmutablePolicy::isDefined() const {
    return (
        _type != UNKNOWN_IMMUTABLE_POLICY
        && _start > 0
        && _duration > 0
    );
}

bool ImmutablePolicy::isExpired() const {
    time_t now;
    time(&now);
    return now > getEndDate();
}

bool ImmutablePolicy::isExtension(const ImmutablePolicy &target) const {
    return
        _type == target.getType()
        && getEndDate() > target.getEndDate();
    ;
}

void ImmutablePolicy::reset() {
    _type = UNKNOWN_IMMUTABLE_POLICY;
    _start = 0;
    _duration = 0;
    _autoRenew = false;
}

time_t ImmutablePolicy::convertStartDateToUTC(const struct tm &t) const {
    // https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html#tag_04_19
    return t.tm_sec +
        t.tm_min*MINUTE_IN_SECONDS +
        t.tm_hour*HOUR_IN_SECONDS +
        t.tm_yday*DAY_IN_SECONDS +
        (t.tm_year-70)*31536000 +
        ((t.tm_year-69)/4)*DAY_IN_SECONDS -
        ((t.tm_year-1)/100)*DAY_IN_SECONDS +
        ((t.tm_year+299)/400)*DAY_IN_SECONDS
    ;
}

std::string ImmutablePolicy::convertTimeToRFC7231(const struct tm &t) const {
    std::string timeStr;
    const size_t dateCount = 32;
    char date[dateCount];
    size_t length = strftime(date, dateCount, "%a, %d %b %Y %T GMT", &t);
    if (length > 0) {
        timeStr = std::string(date, length);
    }
    return timeStr;
}
