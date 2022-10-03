//
// Created by herwig on 29/08/2022.
//

#include "app/client/CCppControllerClient/CCppClientController.hpp"

using namespace std;

using json = nlohmann::json;
#include <iostream>

#ifdef _WIN32
json config =
        {
                {"library", "C:\\DockerVolumes\\cpc\\cmake-build-debug\\cryptoengineApi.dll"}, //location where the shared library resides
                {"vaultDB", "vault.db"}, //the vault to be used
                {"logFile", "logFile"}, //location of the log file
                {"logLevel", "info"}, //you can change this to trace/debug/info/warning/fatal but for normal purposes warning or info should be ok
                {"server", "localhost"}, //location of the server, for testing purposes use localhost
                {"port", "8080"}, //port where the server is started
                {"pillar", "dev"}, //the pillar usually DEV/ACC/PROD
                {"appID", "TEST"}, //the application id, will be assigned after the onboarding, if unknown start with TEST
                {"domain", "DEMO"}, //the domain, assigned after the onboarding
                {"CA", "DEMO"}, //the domain, assigned after the onboarding
                {"authToken", "BUILD"}, //probably BUILD should be the one you want
                {"adminToken", ""}, //filename of the admin token
                {"password", ""} ,//password to open the admin token
                {"keywords", "{\"appID\": \"TEST\", \"autoconfigure\":\"TEST\" }" } //only needed to start up the test during the init, leave blank normally

        };
#else
json config =
        {
                {"library", "./libcryptoengineApi.so"}, //location where the shared library resides
                {"vaultDB", "vault.db"}, //the vault to be used
                {"logFile", "logFile"}, //location of the log file
                {"logLevel", "info"}, //you can change this to trace/debug/info/warning/fatal but for normal purposes warning or info should be ok
                {"server", "host.docker.internal"}, //location of the server, for testing purposes use localhost
                {"port", "8080"}, //port where the server is started
                {"pillar", "dev"}, //the pillar usually DEV/ACC/PROD
                {"appID", "TEST"}, //the application id, will be assigned after the onboarding, if unknown start with TEST
                {"domain", "DEMO"}, //the domain, assigned after the onboarding
                {"CA", "DEMO"}, //the domain, assigned after the onboarding
                {"authToken", "BUILD"}, //probably BUILD should be the one you want
                {"adminToken", ""}, //filename of the admin token
                {"password", ""}, //password to open the admin token
                {"keywords", "{\"appID\": \"TEST\", \"autoconfigure\":\"TEST\" }" }//only needed to start up the test during the init, leave blank normally

        };
#endif

int main() {
    initializeEngine(config);
    string data = "some data";

    //Sign a container
    ExecuteResult signResult(cryptoEngine(config, "signContainer", data, "key", "", ""));
    string uid = getValueJson(signResult.resultJson, "uid", "");
    string signature = getValueJson(signResult.resultJson, "signature", "");
    string signatureErrorCode = getValueJson(signResult.resultJson, "error", "");
    if (signatureErrorCode == "0") cout << "Sign Successful" << endl;
    else cout << "sign failed, the (dummy) signature generated will not be verified in the next step" << endl;

    //Verify the result
    ExecuteResult verifyResult(cryptoEngine(config, "verifyContainer", data, "key", uid, signature));
    string verificationCode = getValueJson(verifyResult.resultJson, "verificationCode", "");
    string verificationErrorCode = getValueJson(verifyResult.resultJson, "error", "");
    if (verificationErrorCode == "0") cout << "Verification Executed" << endl;
    else cout << "Technical error during verification" << endl;
    if (verificationCode == "000") cout << "Verification is successful" << endl;
    else cout << "Verification failed" << endl;


}