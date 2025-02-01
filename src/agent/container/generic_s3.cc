// SPDX-License-Identifier: Apache-2.0

#include "generic_s3.hh"

GenericS3Container::GenericS3Container(int id, std::string bucketName, std::string region, std::string keyId, std::string key, unsigned long int capacity, std::string endpoint, std::string httpProxyIP, unsigned short httpProxyPort, bool useHttp, bool verifySSL)
        : AwsContainer(id, bucketName, region, keyId, key, capacity, endpoint, httpProxyIP, httpProxyPort, useHttp, verifySSL) {
}

