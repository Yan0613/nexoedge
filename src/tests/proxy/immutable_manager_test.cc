// SPDX-License-Identifier: Apache-2.0

#include <map>
#include <vector>
#include <string>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "../../common/config.hh"

#include "../../proxy/proxy.hh"
#include "../../proxy/coordinator.hh"
#include "../../proxy/dedup/dedup.hh"
#include "../../proxy/dedup/impl/dedup_none.hh"

#include "../../proxy/immutable/immutable_policy_store.hh"
#include "../../proxy/immutable/immutable_policy_store_redis.hh"

#include "../../proxy/interfaces/immutable_management_apis.hh"

#include "../../common/util.hh"

using ImmutablePolicyStoreActionResult = ImmutablePolicyStore::ActionResult;
using json = nlohmann::json;

Proxy *proxy = nullptr;
DeduplicationModule *dedup = nullptr;
ProxyCoordinator *coordinator = nullptr;
pthread_t ct;
std::map<int, std::string> agentMap; // container to agent map
BgChunkHandler::TaskQueue taskQueue; // background chunk task queue

ImmutablePolicyStore *store = nullptr;
const char *testFileName = "test file.txt";
const char *testNonExistFileName = "test_non_exits_file.txt";
const char *testDstFileName = "test_file_dst.txt";

std::string apiResponse;

int numFailed = 0;
int numRan = 0;
bool failedSome = false;
bool testViaApis = false;

enum {
    WRITE,
    OVERWRITE,
    APPEND,
    READ,
    RENAME,
    COPY,
    DELETE
};

//=========//
// Setters //
//=========//

void setDefaultTestFile(File &f) {
    f.setName(testFileName, strlen(testFileName));
    //f.setVersion(0);
    f.namespaceId = Config::getInstance().getProxyNamespaceId();
    f.offset = 0;
    f.size = 0;
    f.length = 0;
}

void setNewDstDefaultTestFile(File &f) {
    f.setName(testDstFileName, strlen(testDstFileName));
    //f.setVersion(0);
    f.namespaceId = Config::getInstance().getProxyNamespaceId();
    f.offset = 0;
    f.size = 0;
    f.length = 0;
}

void setNonExistFile(File &f) {
    f.setName(testNonExistFileName, strlen(testNonExistFileName));
    f.setVersion(0);
    f.namespaceId = Config::getInstance().getProxyNamespaceId();
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

//=============//
// Proxy Setup //
//=============//

void initProxy() {
    // create proxy and interface
    coordinator = new ProxyCoordinator(&agentMap); // proxy coordinator
    pthread_create(&ct, NULL, ProxyCoordinator::run, coordinator); // proxy coordinator thread

    dedup = new DedupNone();
    proxy = new Proxy(coordinator, &agentMap, &taskQueue, dedup);
    //printf("Started the proxy. %p\n", proxy);
}

bool uploadAnEmptyFile(bool expectedResult = true) {
    File f;
    setDefaultTestFile(f);
    if (!proxy->writeFile(f)) {
        if (expectedResult) { printf(">> Failed to write an empty file to check policy enforcement!\n"); }
        return false;
    }
    return true;
}

void shutdownProxy() {
    printf("Shutting down the proxy.\n");
    delete proxy;
    delete dedup;
    delete coordinator;

    proxy = nullptr;
    coordinator = nullptr;
    dedup = nullptr;
}

//===================//
// curl client setup //
//===================//

size_t receiveApiResponse(char *incomingData, size_t size, size_t nmemb, void *userdata) {
    apiResponse.append(incomingData, size * nmemb);
    return size * nmemb;
}

long sendPostRequest(std::string path, std::string reqBody) {
    apiResponse.clear();

    long responseCode = 400;
    CURL *curlCli = curl_easy_init();
    if (curlCli) {
        std::string endpoint = "http://localhost:59003" + path;
        if (
            curl_easy_setopt(curlCli, CURLOPT_URL, endpoint.c_str()) == CURLE_OK // set the API endpoint and path
            && curl_easy_setopt(curlCli, CURLOPT_POST, 1) == CURLE_OK // use POST
            && curl_easy_setopt(curlCli, CURLOPT_POSTFIELDS, reqBody.c_str()) == CURLE_OK // set the request body
            && curl_easy_setopt(curlCli, CURLOPT_POSTFIELDSIZE, reqBody.size()) == CURLE_OK // set the request body length
            && curl_easy_setopt(curlCli, CURLOPT_WRITEFUNCTION, receiveApiResponse) == CURLE_OK // set the response retrieval function
            && curl_easy_perform(curlCli) == CURLE_OK // issue the request
        ) {
            curl_easy_getinfo(curlCli, CURLINFO_RESPONSE_CODE, &responseCode);
        }
        curl_easy_cleanup(curlCli); // clean up
    }
    return responseCode;
}

long sendGetRequest(std::string path, std::string reqBody) {
    apiResponse.clear();

    long responseCode = 400;
    CURL *curlCli = curl_easy_init();
    if (curlCli) {
        std::string endpoint = "http://localhost:59003" + path + "?" + reqBody;
        if (
            curl_easy_setopt(curlCli, CURLOPT_URL, endpoint.c_str()) == CURLE_OK // set the API endpoint and path
            && curl_easy_setopt(curlCli, CURLOPT_WRITEFUNCTION, receiveApiResponse) == CURLE_OK // set the response retrieval function
            && curl_easy_setopt(curlCli, CURLOPT_HTTPGET, 1) == CURLE_OK // use POST
            && curl_easy_perform(curlCli) == CURLE_OK // issue the request
        ) {
            curl_easy_getinfo(curlCli, CURLINFO_RESPONSE_CODE, &responseCode);
        }
        curl_easy_cleanup(curlCli); // clean up
    }
    return responseCode;
}

bool extractPolicyFromResponse(ImmutablePolicy &p) {
    try {
        json resBodyJson = json::parse(apiResponse);
        if (
            resBodyJson.contains(ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE) 
            && resBodyJson.contains(ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_START_DATE)
            && resBodyJson.contains(ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_DURATION)
            && resBodyJson.contains(ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_AUTO_RENEW)
        ) {
            p.setStartDate(resBodyJson[ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_START_DATE].get<std::string>());
            p.setType(resBodyJson[ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE].get<std::string>());
            p.setDuration(resBodyJson[ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_DURATION].get<int>());
            p.setRenewable(resBodyJson[ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_AUTO_RENEW].get<int>());
            return true;
        }
    } catch (std::exception &e) {
    }
    return false;
}

bool extractResultFromResponse(std::string &result) {
    try {
        json resBodyJson = json::parse(apiResponse);
        if (resBodyJson.contains(ImmutableManagementApis::REP_BODY_KEY_RESULT)) {
            result = resBodyJson[ImmutableManagementApis::REP_BODY_KEY_RESULT].get<std::string>();
            return true;
        }
    } catch (std::exception &e) {
    }
    return false;
}

long sendPolicyGetRequest(const std::string &name, const std::string &policyType) {
    std::string query;
    query.append(ImmutableManagementApis::REQ_BODY_KEY_FILENAME).append("=").append(Util::urlEncode(name));
    query.append("&").append(ImmutableManagementApis::REQ_BODY_SUBKEY_POLICY_TYPE).append("=").append(Util::urlEncode(policyType));
    //printf("< GET REQ: %s>\n", query.c_str());
    return sendGetRequest(ImmutableManagementApis::REQ_PATH_GET, query);
}

long sendPolicyChangeRequest(const std::string &name, const ImmutablePolicy &policy, const char *path) {
    json reqBodyJson, policyJson;
    ImmutableManagementApis::addPolicyToJson(policy, policyJson);
    // set the file name and policy in the request body
    reqBodyJson[ImmutableManagementApis::REQ_BODY_KEY_POLICY] = policyJson;
    reqBodyJson[ImmutableManagementApis::REQ_BODY_KEY_FILENAME] = name;
    // send the request to the API
    //printf("< %s REQ: %s>\n", path, reqBodyJson.dump().c_str());
    return sendPostRequest(path, reqBodyJson.dump());
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
    ImmutablePolicyStoreActionResult result;
    json reqBodyJson, policyJson, resBodyJson;
    bool okay = false;

    if (!testViaApis) {
        result = store->setPolicyOnFile(f, p);
        okay = result.success() == expectSetToSucceed;
    } else {
        // send the request to the API
        long response = sendPolicyChangeRequest(std::string(f.name, f.nameLength), p, ImmutableManagementApis::REQ_PATH_SET);
        std::string result;
        // check the response
        //printf("< SET REP: %s>\n", apiResponse.c_str());
        okay = response == 200
            && extractResultFromResponse(result)
            && result.compare(expectSetToSucceed? ImmutableManagementApis::REP_BODY_VALUE_RESULT_OK :ImmutableManagementApis::REP_BODY_VALUE_RESULT_FAILED) == 0;
    }
    if (!okay) {
        printf("> Failed to set a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    if (!testViaApis) {
        result = store->getPolicyOnFile(f, p.getType(), rp);
        okay = result.success() == expectGetToSucceed;
    } else {
        long response = sendPolicyGetRequest(f.name, p.getTypeName());
        okay = !expectGetToSucceed || (response == 200 && extractPolicyFromResponse(rp));
        //printf("< GET REP: %s>\n", apiResponse.c_str());
    }
    if (!okay) {
        printf("> Failed to get a policy on a file after setting! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && expectSetToSucceed) {
        printf("> Failed to get the policy set!\n");
        printf(">    Expect %s\n >    Got %s\n", p.to_string().c_str(), rp.to_string().c_str());
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

    // try obtaining a non-existing policy - should fail
    bool okay = false;
    ImmutablePolicy rp;
    ImmutablePolicyStoreActionResult result;
    if (!testViaApis) {
        result = store->getPolicyOnFile(f, ImmutablePolicy::Type::IMMUTABLE, rp);
        okay = result.success();
    } else {
        long response = sendPolicyGetRequest(f.name, ImmutablePolicy::TypeString[ImmutablePolicy::Type::IMMUTABLE]);
        okay = response == 200 && extractPolicyFromResponse(rp);
        //printf("< GET REP: %s>\n", apiResponse.c_str());
    }

    // check if the operation really failed
    if (okay) {
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

    json reqBodyJson, policyJson, resBodyJson;
    bool okay = false;
    ImmutablePolicyStoreActionResult result;

    if (!testViaApis) {
        result = store->extendPolicyOnFile(f, p);
        okay = result.success() == expectToSucceed;
    } else {
        // send the request to the API
        long response = sendPolicyChangeRequest(std::string(f.name, f.nameLength), p, ImmutableManagementApis::REQ_PATH_EXTEND);
        std::string resMsg;
        // check the response
        //printf("< EXTEND REP: %s>\n", apiResponse.c_str());
        okay = response == 200
            && extractResultFromResponse(resMsg)
            && resMsg.compare(expectToSucceed? ImmutableManagementApis::REP_BODY_VALUE_RESULT_OK :ImmutableManagementApis::REP_BODY_VALUE_RESULT_FAILED) == 0;
    }

    // check if the expected result is there
    if (!okay) {
        printf("> Failed to extend a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // get the policy on a file
    if (!testViaApis) {
        result = store->getPolicyOnFile(f, p.getType(), rp);
        okay = result.success();
    } else {
        long response = sendPolicyGetRequest(f.name, p.getTypeName());
        okay = !expectToSucceed || (response == 200 && extractPolicyFromResponse(rp));
        //printf("< GET REP: %s>\n", apiResponse.c_str());
    }

    if (!okay) {
        printf("> Failed to get a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    // check if the policy is correctly retrieved 
    if (p != rp && expectToSucceed) {
        printf("> Failed to get %s after policy extension %s!\n", (expectToSucceed? "the same policy" : "different policies"), (expectToSucceed? "succeeded" : "failed"));
        printf(">    Expect %s\n >    Got %s\n", p.to_string().c_str(), rp.to_string().c_str());
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

    bool okay = false;

    printf("[Policy extension to] %s\n", p.to_string().c_str());

    ImmutablePolicyStoreActionResult result;
    if (!testViaApis) {
        result = store->extendPolicyOnFile(f, p);
        okay = result.success() == false;
    } else {
        // send the request to the API
        long response = sendPolicyChangeRequest(std::string(f.name, f.nameLength), p, ImmutableManagementApis::REQ_PATH_EXTEND);
        std::string resMsg;
        // check the response
        //printf("< EXTEND REP: %s>\n", apiResponse.c_str());
        okay = response == 200
            && extractResultFromResponse(resMsg)
            && resMsg.compare(ImmutableManagementApis::REP_BODY_VALUE_RESULT_FAILED) == 0;
    }

    // check if the expected result is there
    if (!okay) {
        printf("> Got a success for extend a non-existing policy on a file!\n");
        return false;
    }

    if (!testViaApis) {
        result = store->getPolicyOnFile(f, p.getType(), rp);
    } else {
        sendPolicyGetRequest(f.name, p.getTypeName());
        extractPolicyFromResponse(rp);
    }

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
    rp.setRenewable(!enable);

    ImmutablePolicyStoreActionResult result;
    time_t timeNow;
    time(&timeNow);

    bool okay = false;

    if (!testViaApis) {
        result = store->renewPolicyOnFile(f, p.getType(), enable);
        okay = result.success() == expectToSucceed;
    } else {
        long response = sendPolicyChangeRequest(std::string(f.name, f.nameLength), p, ImmutableManagementApis::REQ_PATH_RENEW);
        std::string resMsg;
        // check the response
        //printf("< RENEW REP: %s>\n", apiResponse.c_str());
        okay = response == 200
            && extractResultFromResponse(resMsg)
            && resMsg.compare(expectToSucceed? ImmutableManagementApis::REP_BODY_VALUE_RESULT_OK : ImmutableManagementApis::REP_BODY_VALUE_RESULT_FAILED) == 0;
    }

    if (!okay) {
        printf("> Failed to update a policy on a file! %s\n", result._errorMsg.c_str());
        return false;
    }

    if (!testViaApis) {
        result = store->getPolicyOnFile(f, p.getType(), rp);
    } else {
        sendPolicyGetRequest(f.name, p.getTypeName());
        extractPolicyFromResponse(rp);
    }

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

bool testPolicyMove() {
    if (store == nullptr) { return false; }

    // increment the number of test cases ran
    numRan++;

    File f1, f2;
    setDefaultTestFile(f1);
    setNewDstDefaultTestFile(f2);

    // remove all policies on both files (for a fresh start)
    store->deleteAllPolicies(f1);
    store->deleteAllPolicies(f2);

    // set the policies to the source file
    ImmutablePolicy p;
    ImmutablePolicyStoreActionResult result;
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        setDefaultPolicy(p);
        p.setType(static_cast<ImmutablePolicy::Type>(policyType));
        result = store->setPolicyOnFile(f1, p);
        if (result.success() == false) {
            printf("> Failed to set the policies for policy move.\n");
            store->deleteAllPolicies(f1);
            return false;
        }
        printf("[Policy in store before move] %s\n", p.to_string().c_str());
    }

    // execute the policy migration from the source file to the destination file
    result = store->moveAllPolicies(f1, f2);
    if (result.success() == false) {
        printf("> Failed to move the policies.\n");
        store->deleteAllPolicies(f1);
        return false;
    }
  
    // check the result - no policies remains with the source files, all policies are now with the destination file
    for (int policyType = 0; policyType < static_cast<int>(ImmutablePolicy::Type::UNKNOWN_IMMUTABLE_POLICY); policyType++) {
        ImmutablePolicy rp1, rp2;
        ImmutablePolicy::Type type = static_cast<ImmutablePolicy::Type>(policyType);
        result = store->getPolicyOnFile(f1, type, rp1);
        if (result.success() != false) {
            printf("> Failed to move the %s policies in the policy move (still with the source).\n", ImmutablePolicy::TypeString[type]);
            store->deleteAllPolicies(f1);
            store->deleteAllPolicies(f2);
            return false;
        }
        result = store->getPolicyOnFile(f2, type, rp2);
        if (result.success() == false) {
            printf("> Failed to move the %s policies in the policy move (missing from the destination).\n", ImmutablePolicy::TypeString[type]);
            store->deleteAllPolicies(f1);
            store->deleteAllPolicies(f2);
            return false;
        }
        printf("[Policy in store after move] %s\n", rp2.to_string().c_str());
    }
    
    printf("> Passed the move-policy test.\n");
    return true;
}

bool testEnforcementFile(std::vector<ImmutablePolicy> policies, std::map<int, bool> expectedResults, std::string testType) {
    if (store == nullptr) { return false; }

    File f1, f2;
    setDefaultTestFile(f1);
    setNewDstDefaultTestFile(f2);

    // remove all policies on the file
    store->deleteAllPolicies(f1);
    store->deleteAllPolicies(f2);

    // upload the file
    if (uploadAnEmptyFile() == false) {
        printf("Failed to upload an empty file under %s.", testType.c_str());
        store->deleteAllPolicies(f1);
        store->deleteAllPolicies(f2);
        return false;
    }

    // set all policies to test
    for (auto p : policies) {
        if (store->setPolicyOnFile(f1, p).success() == false) {
            store->deleteAllPolicies(f1);
            store->deleteAllPolicies(f2);
            printf("Failed to set policies on the file for tests under %s.", testType.c_str());
            return false;
        }
    }

    numRan++;

    // test all file operations - expect all to run successfully
    // write
    if (uploadAnEmptyFile(expectedResults[WRITE]) != expectedResults[WRITE]) {
        printf("Failed to write under %s.", testType.c_str());
        return false;
    }
    // overwrite
    if (proxy->overwriteFile(f1) != expectedResults[OVERWRITE]) {
        printf("Failed to overwrite under %s.", testType.c_str());
        return false;
    }
    // append
    if (proxy->appendFile(f1) != expectedResults[APPEND]) {
        printf("Failed to append under %s.", testType.c_str());
        return false;
    }
    // read
    if (proxy->readFile(f1) != expectedResults[READ]) {
        printf("Failed to read under %s.", testType.c_str());
        return false;
    }
    // rename
    if (proxy->renameFile(f1, f2) != expectedResults[RENAME]) {
        printf("Failed to rename under %s.", testType.c_str());
        return false;
    }
    // check the policies goes to the renamed file
    if (expectedResults[RENAME]) {
        for (ImmutablePolicy p : policies) {
            ImmutablePolicy rp1, rp2;
            ImmutablePolicy::Type type = p.getType();
            ImmutablePolicyStore::ActionResult result = store->getPolicyOnFile(f1, type, rp1);
            if (result.success() != false) {
                printf("Failed to update the %s policies after rename (still with the source).\n", ImmutablePolicy::TypeString[type]);
                store->deleteAllPolicies(f1);
                store->deleteAllPolicies(f2);
                return false;
            }
            result = store->getPolicyOnFile(f2, type, rp2);
            if (result.success() == false) {
                printf("Failed to update the %s policies after rename (missing from the destination).\n", ImmutablePolicy::TypeString[type]);
                store->deleteAllPolicies(f1);
                store->deleteAllPolicies(f2);
                return false;
            }
        }
    }
    // copy
    File &sf = expectedResults[RENAME]? f2 : f1;
    File &df = expectedResults[RENAME]? f1 : f2;
    if (proxy->copyFile(sf, df) != expectedResults[COPY]) {
        printf("Failed to copy under %s.", testType.c_str());
        return false;
    }
    // delete
    File &tf = expectedResults[RENAME]? f2 : f1;
    if (proxy->deleteFile(tf) != expectedResults[DELETE]) {
        printf("Failed to delete the renamed file under %s.", testType.c_str());
        return false;
    }

    // remove all policies on the file
    store->deleteAllPolicies(f1);
    store->deleteAllPolicies(f2);

    // clean up
    proxy->deleteFile(f1);
    proxy->deleteFile(f2);

    printf("> Passed the operation test under %s.\n", testType.c_str());
    return true;
}

bool testEnforcementFileNoPolicy() {
    std::map<int, bool> expectedResults;
    expectedResults[WRITE] = true;
    expectedResults[OVERWRITE] = true;
    expectedResults[APPEND] = true;
    expectedResults[READ] = true;
    expectedResults[RENAME] = true;
    expectedResults[COPY] = true;
    expectedResults[DELETE] = true;
    std::vector<ImmutablePolicy> policies;
    return testEnforcementFile(policies, expectedResults, "no policies");
}

bool testEnforcementFileImmutablePolicyValid() {
    std::map<int, bool> expectedResults;
    expectedResults[WRITE] = false;
    expectedResults[OVERWRITE] = false;
    expectedResults[APPEND] = false;
    expectedResults[READ] = true;
    expectedResults[RENAME] = false;
    expectedResults[COPY] = true;
    expectedResults[DELETE] = false;
    std::vector<ImmutablePolicy> policies;
    policies.resize(1); 
    setDefaultPolicy(policies.at(0));
    return testEnforcementFile(policies, expectedResults, "a valid immutable policy");
}

bool testEnforcementFileModificationHoldPolicyValid() {
    std::map<int, bool> expectedResults;
    expectedResults[WRITE] = false;
    expectedResults[OVERWRITE] = false;
    expectedResults[APPEND] = false;
    expectedResults[READ] = true;
    expectedResults[RENAME] = false;
    expectedResults[COPY] = true;
    expectedResults[DELETE] = true;
    std::vector<ImmutablePolicy> policies;
    policies.resize(1); 
    setDefaultPolicy(policies.at(0));
    policies.at(0).setType(ImmutablePolicy::Type::MODIFICATION_HOLD);
    return testEnforcementFile(policies, expectedResults, "a valid modification-hold policy");
}

bool testEnforcementFileDeletionHoldPolicyValid() {
    std::map<int, bool> expectedResults;
    expectedResults[WRITE] = true;
    expectedResults[OVERWRITE] = true;
    expectedResults[APPEND] = true;
    expectedResults[READ] = true;
    expectedResults[RENAME] = true;
    expectedResults[COPY] = true;
    expectedResults[DELETE] = false;
    std::vector<ImmutablePolicy> policies;
    policies.resize(1); 
    setDefaultPolicy(policies.at(0));
    policies.at(0).setType(ImmutablePolicy::Type::DELETION_HOLD);
    return testEnforcementFile(policies, expectedResults, "a valid deletion-hold policy");
}

bool testEnforcementFileAccessHoldPolicyValid() {
    std::map<int, bool> expectedResults;
    expectedResults[WRITE] = false;
    expectedResults[OVERWRITE] = false;
    expectedResults[APPEND] = false;
    expectedResults[READ] = false;
    expectedResults[RENAME] = false;
    expectedResults[COPY] = false;
    expectedResults[DELETE] = false;
    std::vector<ImmutablePolicy> policies;
    policies.resize(1); 
    setDefaultPolicy(policies.at(0));
    policies.at(0).setType(ImmutablePolicy::Type::ACCESS_HOLD);
    return testEnforcementFile(policies, expectedResults, "a valid access-hold policy");
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

    // test policy migration - should success
    if (!testViaApis) {
        numFailed += !testPolicyMove();
    }

    printf(">> Passed %d of %d tests on policy store %s. <<\n", numRan - numFailed, numRan, (testViaApis? "via APIs" : "via direct calls"));
    failedSome = failedSome || numFailed > 0;
    numFailed = 0; numRan = 0;
}

void policyEnforcementTests() {
    // no policy
    numFailed += !testEnforcementFileNoPolicy();

    // immutable data
    numFailed += !testEnforcementFileImmutablePolicyValid();

    // modification hold
    numFailed += !testEnforcementFileModificationHoldPolicyValid();
    
    // access hold
    numFailed += !testEnforcementFileAccessHoldPolicyValid();

    // deletion hold
    numFailed += !testEnforcementFileDeletionHoldPolicyValid();

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

    // init a proxy
    initProxy();

    // reset the test state by removing all policies 
    cleanup();

    // policy management (direct calls)
    testViaApis = false;
    policyStoreTests();
    cleanup();
    if (failedSome) { goto cleanup; }

    // policy management (API calls)
    testViaApis = true;
    policyStoreTests();
    cleanup();
    if (failedSome) { goto cleanup; }

    // policy enforcement
    policyEnforcementTests();
    cleanup();
    if (failedSome) { goto cleanup; }

    printf(">>> Passed all tests! <<<\n");

cleanup:

    shutdownProxy();
    delete store;
    store = nullptr;

    assert(!failedSome);

    return 0;
}
