#include "../../common/config.hh"

#include "../../proxy/immutable/immutable_policy_store.hh"
#include "../../proxy/immutable/immutable_policy_store_redis.hh"

using ImmutablePolicyType = ImmutablePolicy::ImmutablePolicyType;
using ImmutablePolicyStoreActionResult = ImmutablePolicyStore::ImmutablePolicyStoreActionResult;


ImmutableRedisPolicyStore *store = nullptr;
const char *testFileName = "test_file.txt";

void testPolicySet() {
    if (store == nullptr) { return; }

    File f;
    f.setName(testFileName, strlen(testFileName));
    f.setVersion(0);
    f.namespaceId = 123;

    time_t timeNow;
    time(&timeNow);

    ImmutablePolicy p, rp;
    p.setType(ImmutablePolicyType::IMMUTABLE);
    p.setStartDate(timeNow);
    p.setDuration(14);
    p.setRenewable(false);

    // set the policy on a file
    ImmutablePolicyStoreActionResult result = store->setPolicyOnFile(f, p);
    if (!result.success()) {
        printf("> Failed to set a policy on a file! %s\n", result._errorMsg.c_str());
        exit(1);
    }

    // get the policy on a file
    result = store->getPolicyOnFile(f, p.getType(), rp);
    if (!result.success()) {
        printf("> Failed to get a policy on a file! %s\n", result._errorMsg.c_str());
        exit(1);
    }

    // check if the policy is correctly retrieved 
    if (p != rp) {
        printf("> Failed to get the policy set!\n");
        exit(1);
    }
    printf("> Pass the set policy test.\n");
}

void testNonExistPolicyGet() {
    if (store == nullptr) { return; }

    File f;
    f.setName(testFileName, strlen(testFileName));
    f.setVersion(0);
    f.namespaceId = 3;

    ImmutablePolicy rp;
    ImmutablePolicyStoreActionResult result = store->getPolicyOnFile(f, ImmutablePolicyType::IMMUTABLE, rp);
    if (!result.success()) {
        printf("> Get a successful result for an non-existing policy on a file!\n");
        exit(1);
    }

    printf("> Pass the non-existng policy inquiry test.\n");
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

    testPolicySet();
    testNonExistPolicyGet();
    // TODO test duplicate policy set

    return 0;
}
