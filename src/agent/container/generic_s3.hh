// SPDX-License-Identifier: Apache-2.0

#ifndef __GENERIC_CONTAINER_HH__
#define __GENERIC_CONTAINER_HH__

#include <string>

#include "aws_s3.hh"

class GenericS3Container : public AwsContainer {
public:
    GenericS3Container(int id, std::string bucketName, std::string region, std::string keyId, std::string key, unsigned long int capacity, std::string endpoint, std::string httpProxyIP = "", unsigned short httpProxyPort = 0, bool useHttp = false, bool verifySSL = false);

private:
};

#endif // __GENERIC_CONTAINER_HH__

