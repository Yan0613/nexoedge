// SPDX-License-Identifier: Apache-2.0

#include "../../common/config.hh"

#include "../../proxy/immutable/immutable_policy_store.hh"
#include "../../proxy/immutable/immutable_policy_store_redis.hh"

using ImmutablePolicyStoreActionResult = ImmutablePolicyStore::ActionResult;


ImmutablePolicyStore *store = nullptr;
const char *testFileName = "test_file.txt";

int numFailed = 0;
int numRan = 0;
bool failedSome = false;

//=========//
// Setters //
//=========//

void setDefaultTestFile(File &f) {
    f.setName(testFileName, strlen(testFileName));
    f.setVersion(0);
    f.namespaceId = 123;
}

void setNonExistFile(File &f) {
    f.setName(testFileName, strlen(testFileName));
    f.setVersion(0);
    f.namespaceId = 3;
}

void setDefaultPolicy(
        ImmutablePolicy &p,
        time_t startTime = 0,
        ImmutablePolicy::Type type = ImmutablePolicy::Type::IMMUTABLE,
        unsigned short duration = 14,
        bool autoRenew = false
) {
    time_t policyTime = startTime;
    if (policyTime == 0) {
        time(&policyTime);
    }
    p = ImmutablePolicy(type, policyTime, duration, autoRenew);
}

//==========//
// Clean up //
//==========//

void cleanup() {
    if (store == nullptr) { return; }
    File f;
    setDefaultTestFile(f);
    store->deleteAllPolicies(f);
}

//==============================//
// Policy Store Test Operations //
//==============================//

bool testPolicySet(time_t startTime = 0, bool autoRenew = false, bool expectSetToSucceed = true, bool expectGetToSucceed = true) {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setDefaultTestFile(f);

    ImmutablePolicy p, rp;
    setDefaultPolicy(p);
    if (startTime > 0) { p.setStartDate(startTime); }
    p.setRenewable(autoRenew);

    printf("[Policy to set] %s\n", p.to_string().c_str());

    // set the policy on a file
    ImmutablePolicyStoreActionResult result = store->setPolicyOnFile(f, p);
    if (result.success() != expectSetToSucceed) {
        printf("> Failed to set a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    result = store->getPolicyOnFile(f, p.getType(), rp);
    if (result.success() != expectGetToSucceed) {
        printf("> Failed to get a policy on a file after setting! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && expectSetToSucceed) {
        printf("> Failed to get the policy set!\n");
        return false;
    }

    printf("> Passed the set-policy test (%s as expected).\n", (expectSetToSucceed? "succeeded" : "failed"));
    return true;
}

bool testNonExistPolicyGet() {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setNonExistFile(f);

    ImmutablePolicy rp;
    ImmutablePolicyStoreActionResult result = store->getPolicyOnFile(f, ImmutablePolicy::Type::IMMUTABLE, rp);
    if (result.success()) {
        printf("> Get a successful result for an non-existing policy on a file!\n");
        return false;
    }

    printf("> Passed the non-existng policy inquiry test.\n");
    return true;
}

bool testPolicyExtend(int delta = 1, bool expectToSucceed = true) {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setDefaultTestFile(f);

    ImmutablePolicy p, rp;
    setDefaultPolicy(p);
    p.setDuration(p.getDuration() + delta);

    ImmutablePolicyStoreActionResult result = store->extendPolicyOnFile(f, p);

    // check if the expected result is there
    if (result.success() != expectToSucceed) {
        printf("> Failed to extend a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    result = store->getPolicyOnFile(f, p.getType(), rp);
    if (!result.success()) {
        printf("> Failed to get a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && expectToSucceed) {
        printf("> Failed to get %s after policy extension %s!\n", (expectToSucceed? "the same policy" : "different policies"), (expectToSucceed? "succeeded" : "failed"));
        return false;
    }

    printf("> Passed the extend-policy test (%s as expected).\n", (expectToSucceed? "succeeded" : "failed"));
    return true;
}

bool testNonExistPolicyExtend() {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setNonExistFile(f);

    ImmutablePolicy p, rp;
    setDefaultPolicy(p);
    p.setDuration(p.getDuration() + 1);

    printf("[Policy extension to] %s\n", p.to_string().c_str());

    ImmutablePolicyStoreActionResult result = store->extendPolicyOnFile(f, p);

    // check if the expected result is there
    if (result.success() != false) {
        printf("> Got a success for extend a non-existing policy on a file!\n");
        return false;
    }

    result = store->getPolicyOnFile(f, p.getType(), rp);
    printf("[Policy in store] %s\n", rp.to_string().c_str());

    printf("> Passed the non-existing policy extension test.\n");
    return true;
}

bool testPolicyRenewable(bool enable, time_t startTime = 0, bool expectToSucceed = true) {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setDefaultTestFile(f);

    ImmutablePolicy p, rp;
    setDefaultPolicy(p);
    p.setStartDate(startTime);
    p.setRenewable(enable);

    ImmutablePolicyStoreActionResult result;
    time_t timeNow;
    time(&timeNow);
    result = store->renewPolicyOnFile(f, p.getType(), enable);

    if (result.success() != expectToSucceed) {
        printf("> Failed to update a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    result = store->getPolicyOnFile(f, p.getType(), rp);

    if (p.isRenewable() != rp.isRenewable() && expectToSucceed) {
        printf("> Failed to get the expected auto renew state of the policy!\n");
        return false;
    }

    if (expectToSucceed && !enable && timeNow >= rp.getEndDate()) {
        printf("> Failed to get the expected end date of the policy! (expected beyond %lu but got %lu)\n", timeNow, rp.getEndDate());
        return false;
    }

    printf("[Policy in store] %s\n", rp.to_string().c_str());

    printf("> Passed the renew-policy test (%s as expected).\n", (expectToSucceed? "succeeded" : "failed"));
    return true;
}

//============//
// Test Cases //
//============//

void policyStateTests() {
    ImmutablePolicy p;

    // test policy initial state - should be undefined
    assert(!p.isDefined() && "Check if a policy is defined.");

    // test the creation of all possible policy types - should succeed
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        assert(p.setType(static_cast<ImmutablePolicy::Type>(policyType)) && "Set a valid policy type.");
        assert(p.getType() == policyType && "Check policy type set.");
    }

    // test set start date - should succeed
    time_t timeNow;
    time(&timeNow);
    assert(p.setStartDate(timeNow) && "Set a valid policy start date.");
    assert(p.getStartDate() == timeNow / 86400 * 86400 && "Check the updated start date after setting a valid policy start date.");

    // test set an invalid start date at the epoch - should fail
    assert(!p.setStartDate(0) && "Set an invalid policy start date (epoch).");

    // test set a valid period - should succeed
    unsigned short days = 100;
    assert(p.setDuration(days) && "Set a valid policy valid period.");
    assert(p.getDuration() == days && "Check the update valid period after setting a valid policy valid period.");

    // test set an invalid period - should fail
    assert(!p.setDuration(0) && "Set an invalid policy valid period.");

    // test policy has not expired - should succeed
    assert(!p.isExpired() && "Check the expiration status of a non-renewable policy with a valid period.");

    // test policy has expired - should succeed
    assert(p.setStartDate(timeNow - 86400 * 2));
    assert(p.setDuration(1));
    assert(p.isExpired() && "Check the expiration status of a non-renewable policy with an 'expired' valid period.");
    
    // test policy renewable setting - should succeed
    assert(p.setRenewable(true));
    assert(p.isRenewable() && "Check the auto renew status after enabling auto renew");
    assert(!p.isExpired() && "Check the expiration status of a renewable policy with an 'expired' valid period.");
    assert(p.setRenewable(false));
    assert(!p.isRenewable() && "Check the auto renew status after disabling auto renew");

    printf(">> Passed all tests on policy state. <<\n");
}

void policyStoreTests() {
    // test policy set in future - should fail
    time_t futureTime;
    time(&futureTime);
    futureTime += 84600;
    numFailed += !testPolicySet(futureTime, /* auto renew */ false, /* expect a SET success */ false, /* expect a GET succes */ false);

    // test policy set in past - should fail
    time_t passTime;
    time(&passTime);
    passTime -= 84600 * 15;
    numFailed += !testPolicySet(passTime, /* auto renew */ false, /* expect a SET success */ false, /* expect a GET succes */ false);

    // test policy set - should succeed
    numFailed += !testPolicySet();

    cleanup();

    // test policy set with renewable - should succeed
    time(&passTime);
    passTime -= 84600 * 15;
    numFailed += !testPolicySet(passTime, /* auto renew */ true);

    // test policy renew disabling - should succeed
    numFailed += !testPolicyRenewable(/* set to auto renew */ false);

    // test retrieval of an non-existing policy - should fail
    numFailed += !testNonExistPolicyGet();

    // test duplicate policy set - should fail
    numFailed += !testPolicySet(0, /* auto renew */ false, /* expect a success */ false);

    // test policy extension - should succeed
    numFailed += !testPolicyExtend();

    // test policy no change on extension - should fail
    numFailed += !testPolicyExtend(0, /* expect a success */ false);

    // test policy shorten - should fail
    numFailed += !testPolicyExtend(-1, /* expect a success */ false);

    // test policy renew eanbling - should succeed
    numFailed += !testPolicyRenewable(/* set to auto renew */ true);

    // test policy renew disabling - should succeed
    numFailed += !testPolicyRenewable(/* set to auto renew */ false);

    printf(">> Passed %d of %d tests on policy store. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;
}

void policyManagementTests() {
    // TODO
    printf(">> Passed %d of %d tests on policy management. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;
}

void policyEnforcementTests() {
    // TODO
    printf(">> Passed %d of %d tests on policy enforcement. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;
}


//======//
// Main //
//======//

int main (int argc, char **argv) {
    // config
    Config &config = Config::getInstance();
    if (argc > 1) {
        config.setConfigPath(std::string(argv[1]));
    } else {
        config.setConfigPath();
    }
    
    if (!config.glogToConsole()) {
        FLAGS_log_dir = config.getGlogDir().c_str();
        printf("Output log to %s\n", config.getGlogDir().c_str());
    } else {
        FLAGS_logtostderr = true;
        printf("Output log to console\n");
    }
    FLAGS_minloglevel = config.getLogLevel();
    google::InitGoogleLogging(argv[0]);

    // seed the random number sequence
    //srand(987123);

    // policy state
    policyStateTests();

    // init the policy store
    store = new ImmutableRedisPolicyStore();

    // reset the test state by removing all policies 
    cleanup();

    // policy management
    policyStoreTests();
    cleanup();
    assert(!failedSome);

    policyManagementTests();
    cleanup();
    assert(!failedSome);

    // policy enforcement
    policyEnforcementTests();
    cleanup();
    assert(!failedSome);

    return 0;
}
