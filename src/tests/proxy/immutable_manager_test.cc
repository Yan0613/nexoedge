#include "../../common/config.hh"

#include "../../proxy/immutable/immutable_policy_store.hh"
#include "../../proxy/immutable/immutable_policy_store_redis.hh"

using ImmutablePolicyStoreActionResult = ImmutablePolicyStore::ActionResult;


ImmutableRedisPolicyStore *store = nullptr;
const char *testFileName = "test_file.txt";

int numFailed = 0;
int numRan = 0;
bool failedSome = false;


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

void setTestPolicy(
        ImmutablePolicy &p,
        time_t startTime = 0,
        ImmutablePolicy::Type type = ImmutablePolicy::Type::IMMUTABLE,
        unsigned short duration = 14,
        bool autoRenew = false
) {
    p.setType(type);
    if (startTime == 0) {
        time_t timeNow;
        time(&timeNow);
        p.setStartDate(timeNow);
    } else {
        p.setStartDate(startTime);
    }
    p.setDuration(duration);
    p.setRenewable(autoRenew);
}

bool testPolicySet(bool expectToFail = false) {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setDefaultTestFile(f);

    ImmutablePolicy p, rp;
    setTestPolicy(p);

    // set the policy on a file
    ImmutablePolicyStoreActionResult result = store->setPolicyOnFile(f, p);
    if (result.success() == expectToFail) {
        printf("> Failed to set a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    result = store->getPolicyOnFile(f, p.getType(), rp);
    if (!result.success()) {
        printf("> Failed to get a policy on a file after setting! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && !expectToFail) {
        printf("> Failed to get the policy set!\n");
        return false;
    }

    printf("> Pass the set-policy test (%s as expected).\n", (expectToFail? "failed" : "succeeded"));
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
    if (!result.success()) {
        printf("> Get a successful result for an non-existing policy on a file!\n");
        return false;
    }

    printf("> Pass the non-existng policy inquiry test.\n");
    return true;
}

bool testPolicyExtend(int delta = 1, bool expectToFail = false) {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setDefaultTestFile(f);

    ImmutablePolicy p, rp;
    setTestPolicy(p);
    p.setDuration(p.getDuration() + delta);

    ImmutablePolicyStoreActionResult result = store->extendPolicyOnFile(f, p);

    // check if the expected result is there
    if (result.success() != !expectToFail) {
        printf("> Failed to extend a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    result = store->getPolicyOnFile(f, p.getType(), rp);
    if (!result.success()) {
        printf("> Failed to get a policy on a file after setting! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && !expectToFail) {
        printf("> Failed to get %s after policy extension %s!\n", (expectToFail? "different policies" : "the same policy"), (expectToFail? "failed" : "succeeded"));
        return false;
    }

    printf("> Pass the extend-policy test (%s as expected).\n", (expectToFail? "failed" : "succeeded"));
    return true;
}

bool testNonExistPolicyExtend() {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f;
    setNonExistFile(f);

    ImmutablePolicy p, rp;
    setTestPolicy(p);
    p.setDuration(p.getDuration() + 1);

    ImmutablePolicyStoreActionResult result = store->extendPolicyOnFile(f, p);

    // check if the expected result is there
    if (result.success() != false) {
        printf("> Got a success for extend a non-existing policy on a file!\n");
        return false;
    }

    printf("> Pass the non-existing policy extension test.\n");
    return true;
}
void cleanup() {
    if (store == nullptr) { return; }
    File f;
    setDefaultTestFile(f);
    store->deleteAllPolicies(f);
}


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

    store = new ImmutableRedisPolicyStore();

    // reset the test state by removing all policies 
    cleanup();

    // TODO policy state

    printf(">> Pass %d of %d tests on policy state. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;

    // policy management

    // test policy set - should success
    numFailed += !testPolicySet(false);

    // test retrieval of an non-existing policy - should fail
    numFailed += !testNonExistPolicyGet();

    // test duplicate policy set - should fail
    numFailed += !testPolicySet(true);

    // test policy extension - should success
    numFailed += !testPolicyExtend();

    // test policy no change on extension - should fail
    numFailed += !testPolicyExtend(0, /* expected to fail */ true);

    // test policy shorten - should fail
    numFailed += !testPolicyExtend(-1, /* expected to fail */ true);

    numFailed += !testPolicyExtend(-1, /* expected to fail */ true);
    printf(">> Pass %d of %d tests on policy management. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;

    // TODO policy enforcement

    printf(">> Pass %d of %d tests on policy enforcement. <<\n", numRan - numFailed, numRan);
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;

    return failedSome? 1 : 0;
}
