// SPDX-License-Identifier: Apache-2.0

#include <stdexcept>

#include "../common/define.hh"
#include "./immutable_policy.hh"

const char *ImmutablePolicy::TypeString[] = {
    "immutable",
    "modification-hold",
    "deletion-hold",
    "access-hold",
    "unknown"
};

// convert the time from time_t to struct tm
bool convertTimet2Tm(const time_t tt, struct tm &tm) {
    return gmtime_r(&tt, &tm) != nullptr;
}

ImmutablePolicy::ImmutablePolicy() {
    reset();
}

ImmutablePolicy::ImmutablePolicy(ImmutablePolicy::Type type, time_t startDate, unsigned short duration) noexcept (false) {
    if (!setType(type) || !setStartDate(startDate) || !setDuration(duration) || !setRenewable(false)) {
        throw std::invalid_argument("Invalid argument for immutable policy setup.");
    }
}

ImmutablePolicy::ImmutablePolicy(ImmutablePolicy::Type type, time_t startDate, unsigned short duration, bool autoRenew) noexcept (false) {
    if (!setType(type) || !setStartDate(startDate) || !setDuration(duration) || !setRenewable(autoRenew)) {
        throw std::invalid_argument("Invalid argument for immutable policy setup.");
    }
}

ImmutablePolicy::~ImmutablePolicy() {
    reset();
}

bool ImmutablePolicy::setType(const ImmutablePolicy::Type type) {
    _type = type;
    return true;
}

ImmutablePolicy::Type ImmutablePolicy::getType() const {
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
    time_t newTime = convertStartDateToUTC(newStartDate);

    // the policy should not start at epoch
    if (newTime == 0) { return false; }

    _start = newTime;

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
    // must be at least one day
    if (days == 0) { return false; }

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
    return !isRenewable() && now > getEndDate();
}

bool ImmutablePolicy::isStarted() const {
    time_t now;
    time(&now);
    return now >= getStartDate();
}

bool ImmutablePolicy::isExtension(const ImmutablePolicy &target) const {
    return
        _type == target.getType()
        && getEndDate() > target.getEndDate();
    ;
}

std::string ImmutablePolicy::to_string() const {
    std::string rep;
    rep.append(" type: ").append(TypeString[_type]).append(";");
    rep.append(" start: ").append(getStartDateString()).append(";");
    rep.append(" end: ").append(getEndDateString()).append(";");
    rep.append(" auto-renew: ").append(std::to_string(isRenewable())).append(";");

    return rep;
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
