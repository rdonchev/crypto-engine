#ifndef CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_HPP
#define CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_HPP
//
// Created by herwig on 29/08/2022.
// marshalling functions to call the shared library for cryptoengine
#include <iostream>
using namespace std;
#include "CCppClientController.h"
#include "json.hpp"

#include <regex>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

using json = nlohmann::json;



/**
     * simple function to extract some tag out of a json and return a default value if not found
     * @param js json object
     * @param tag name of the tag
     * @param defaultValue default value to be returned if missing
     * @return tag value or default value as a string
     */
string getValueJson(json &js, string tag, string defaultValue){
    try
    {
        // use at() on a non-object type
        return js.at(tag);
    }
    catch (...)
    {
        return defaultValue;
    }
}

/**
     * simple function to extract some tag out of a string, the string is enclosed with <tag> targetString </tag>, the search is NOT case sensitive
     * @param tag name of the tag
     * @param string string which should contain the tag
     * @return either the targetString or an empty string (if not found)
     */

string baseExtract(string tag, string str){

// Your regex, in this specific scenario
// Will NOT work for nested <column> tags!
    //std::regex rgx("<"+tag+">([\\s\\S]*?)</"+tag+">",std::regex::icase);
    string tagstr="<"+tag+">([\\s\\S]*?)<\\/"+tag+">";
    std::regex rgx(tagstr,std::regex::icase);
    std::smatch match;

// Try to match it
    if (regex_search(str, match, rgx))
    {
        return match[1];
    }
    return "";
}

/**
     * utility class to handle the result returned by the cryptoEngine
     * this will parse the returned string and position the different elements
     */
class ExecuteResult {
public:
    /* the result as json */
    json resultJson;
    /* the authorization string returned by the server */
    string authorization;
    /* the full string returned by the server */
    string output;
    /* the consoleError in the string returned by the function, these are intended for logging purposes, its not the result of the error code returnded by the opereation, this will be part of the resultJson */
    string consoleError;
    /**
     * construct the result from a string
     * @param resultString the string returned by the cryptoEngine
     */
    ExecuteResult(string resultString){
        string jsonstring=baseExtract("JSON", resultString);
        output=resultString;
        authorization=baseExtract("authorization", resultString);
        consoleError=baseExtract("ERROR", resultString);
        try {
            resultJson=json::parse(jsonstring);
        } catch (...){

        }

    }
};





#ifdef _WIN32
HINSTANCE cryptoengine_lib_handle=NULL;
#else
void * cryptoengine_lib_handle=NULL;
#endif

/**
     * initialize the engine - load the shared library and initialize it
     * CORE Routine for calling the API
     * IMPORTANT: use this function only 1 time when you start your process!!!!!!!!!!!!!!!!! if you do multi threading, also use this one time per process (not per thread)
     * @param library name of the library which contains the engine
     * @param vaultDB Location of vault.db file, preferably use absolute pathnames, it is recommended to put the vault db on local storage, or a ram disk for fast access, in case the initialization fails (consistency check fail) please restore the last known good file
     * @param logFile path of the log file, if not provided, then logging will be disabled, if enable different types of rotating log files will be generated with different extensions (accessLog, serviceLog, log, clientAccessLog, serverCallLog, see logFiles.md for details)
     * @param logLevel level (trace/debug/info/warning/error/fatal) of logging expected in the global log file, usually logging errors is sufficient
     * @param server server to which to connect, can be either separated by colons (to specify different server names only) or sepearated by comma then you can speficy "server:port,server2:port2"
     * @param port port to use for the server
     * @param pillar pillar in which we are running
     * @param keywords json text with keywords {"keyword": "value", ...}, used to specify eventual additional options for the operation
     * @return 0 for successfull execution, 1 for vault consistency check failure, 2 for technical error
     */
int initializeEngine(string library, string vaultDB, string logFile, string logLevel, string server, string port, string pillar, string keywords){ //only to be executed ONCE per process, so all threads should use the same values

    tDCCppInitialize initialize;
#ifdef _WIN32

    cryptoengine_lib_handle = LoadLibrary(TEXT(library.c_str()));
    if (cryptoengine_lib_handle == NULL) {
        printf("ERROR: unable to load DLL\n");
        return 1;
    }

    // Get function pointer
    initialize = (tDCCppInitialize) GetProcAddress(cryptoengine_lib_handle, "CCppInitialize");
    if (initialize == NULL) {
        printf("ERROR: unable to find initialization DLL function\n");
        FreeLibrary(cryptoengine_lib_handle);
        cryptoengine_lib_handle=NULL;
        return 1;
    }
    int rc=(initialize)(vaultDB.c_str(),
                        logFile.c_str(),
                        logLevel.c_str(),
                        server.c_str(),
                        port.c_str(),
                        pillar.c_str(),
                        keywords.c_str());
    return rc;

#else
    cryptoengine_lib_handle = dlopen(library.c_str(),RTLD_NOW);
    if(cryptoengine_lib_handle==NULL) {
        /* ERROR HANDLING */
        printf("ERROR: unable to load so\n");
        return 1;
    }
    initialize = (tDCCppInitialize)
            dlsym(cryptoengine_lib_handle,"CCppInitialize");
    if(initialize==NULL) {
        printf("ERROR: unable to find initialization shared libary function\n");
        /* ERROR HANDLING */
    }
    int rc=(*initialize)(vaultDB.c_str(),
                        logFile.c_str(),
                        logLevel.c_str(),
                        server.c_str(),
                        port.c_str(),
                        pillar.c_str(),
                        keywords.c_str());
    return rc;
#endif
    return 0;




}

/**
     * initialize the engine - load the shared library and initialize it
     * IMPORTANT: use this function only 1 time when you start your process!!!!!!!!!!!!!!!!! if you do multi threading, also use this one time per process (not per thread)
     * this function takes a config json as input
     * json config =
        {
                {"vaultDB", "vault.db"},
                {"logFile", "logFile"},
                {"logLevel", "info"},
                {"server", "localhost"},
                {"port", "8080"},
                {"pillar", "dev"},
                {"library", "C:\\DockerVolumes\\cpc\\cmake-build-debug\\cryptoengineApi.dll"}
        };
     * @param vaultDB Location of vault.db file, preferably use absolute pathnames, it is recommended to put the vault db on local storage, or a ram disk for fast access, in case the initialization fails (consistency check fail) please restore the last known good file
     * @param logFile path of the log file, if not provided, then logging will be disabled, if enable different types of rotating log files will be generated with different extensions (accessLog, serviceLog, log, clientAccessLog, serverCallLog, see logFiles.md for details)
     * @param logLevel level (trace/debug/info/warning/error/fatal) of logging expected in the global log file, usually logging errors is sufficient
     * @param server server to which to connect, can be either separated by colons (to specify different server names only) or sepearated by comma then you can speficy "server:port,server2:port2"
     * @param port port to use for the server
     * @param pillar pillar in which we are running
     * @param keywords json text with keywords {"keyword": "value", ...}, used to specify eventual additional options for the operation
     * @return 0 for successfull execution, 1 for vault consistency check failure, 2 for technical error
     */
int initializeEngine(json &config){ //only to be executed ONCE per process, so all threads should use the same values

    string libname= getValueJson(config, "library", "");

    int rc=initializeEngine(libname,
                            getValueJson(config, "vaultDB", "vault.db"),
                            getValueJson(config, "logFile", ""),
                            getValueJson(config, "logLevel", ""),
                            getValueJson(config, "server", "localhost"),
                            getValueJson(config, "port", "8080"),
                            getValueJson(config, "pillar", ""),
                            getValueJson(config, "keywords", ""));
    return rc;




}


/**
  * Execute a command on the CryptoEngine, please check the list of available commands in the documentation
  * CORE Routine for calling the API
  * typical usage
  * - String encryptedJson= cryptoEngine("encryptPublicRSA","appID", "data","key","authToken","adminToken", "password", "ca", "domain"); // encryption of data with RSA
  * - String decryptedJson= cryptoEngine("decryptPrivateRSA","appID", "encryptedData","key","authToken","adminToken", "password", "ca", "domain"); // decryption of data with RSA
  * - String signatureJson= cryptoEngine("signRSA","appID", "data","key","authToken","adminToken", "password", "ca", "domain"); // signing of data with RSA
  * @param command The Command to be executed: please check the documentation for the list of available commands
  * @param appID The appID from this application, defined by intake of crypto service
  * @param data The data to be treated
  * @param key The key to be used
  * @param authToken The authentication token calculated by the application or BUILD if not applicable
  * @param adminToken The admin token for the application provided by crypto key custodians, or generated during build of the application
  * @param password The password for the admin token
  * @param CA The CA to be used for this operation
  * @param domain The domain (intermediate cert to be used for this operation
  * @param signature The signature which needs to be verified
  * @param uid The unique id of the data (e.g. IV for aes)
  * @param keywords json text with keywords {"keyword": "value", ...}, used to specify eventual additional options for the operation
  * @param outFile The file result  upon successfull completion
  * @param errFile The file will be moved to the errFile (name) upon failure or it remains at its location if this argument is not specified
  * @param archiveFile Upon successfull completeion te file will be moved to this filename
  * @return crypto operations return a CCppResult with a string (char*) which contains tags:
  *          - <ERROR>errors generated during processing</ERROR>
  *          - <AUTHENTICATON>the authentication token received from the server, can be used to verify the data coming from the server</AUTHENTICATON>
  *          - <JSON>the json returned from the server, warning this data is in the transport format between client and server (usually base64 encoded) because you need to be able to verify the data within the application</JSON>
  * IMPORTANT: Free the CCppResult after use calling freeCCppResult
  */
string cryptoEngine(string command, string appID, string &data, string key, string authToken,  string adminToken, string password,
                    string CA, string domain, string uid, string signature, string outFile, string errFile, string archiveFile,
                    string keywords){

    tDCryptoEngine cryptoEngineFunct;
#ifdef _WIN32
    if (cryptoengine_lib_handle == NULL) {
        printf("ERROR: unable to load DLL\n");
        return "";
    }
    // Get function pointer
    cryptoEngineFunct = (tDCryptoEngine) GetProcAddress(cryptoengine_lib_handle, "CCppCryptoEngine");
    if (cryptoEngineFunct == NULL) {
        printf("ERROR: unable to find cryptoengine  DLL function\n");
        FreeLibrary(cryptoengine_lib_handle);
        cryptoengine_lib_handle=NULL;
        return "";
    }
    CCppResult *res =(cryptoEngineFunct)(command.c_str(), appID.c_str(),  data.c_str(),  key.c_str(),  authToken.c_str(),   adminToken.c_str(),  password.c_str(),
             CA.c_str(),  domain.c_str(),  uid.c_str(),  signature.c_str(),  outFile.c_str(),  errFile.c_str(),  archiveFile.c_str(),
             keywords.c_str());
    string result=string(res->string,res->size);
    TDFreeCCppResult freeFunc;
    freeFunc = (TDFreeCCppResult) GetProcAddress(cryptoengine_lib_handle, "freeCCppResult");
    if (freeFunc == NULL) {
        printf("ERROR: unable to find free  DLL function\n");
        FreeLibrary(cryptoengine_lib_handle);
        cryptoengine_lib_handle=NULL;
        return "";
    }
    (freeFunc)(res);
    return result;

#else
    if(cryptoengine_lib_handle==NULL) {
        /* ERROR HANDLING */
        printf("ERROR: unable to load so\n");
        return "";
    }
    cryptoEngineFunct = (tDCryptoEngine)
            dlsym(cryptoengine_lib_handle,"CCppCryptoEngine");
    if(cryptoEngineFunct==NULL) {
        printf("ERROR: unable to find cryptoengine shared libary function\n");
        /* ERROR HANDLING */
    }
    CCppResult *res =(*cryptoEngineFunct)(command.c_str(), appID.c_str(),  data.c_str(),  key.c_str(),  authToken.c_str(),   adminToken.c_str(),  password.c_str(),
                             CA.c_str(),  domain.c_str(),  uid.c_str(),  signature.c_str(),  outFile.c_str(),  errFile.c_str(),  archiveFile.c_str(),
                             keywords.c_str());;
    string result=string(res->string,res->size);
    TDFreeCCppResult freeFunc;
    freeFunc = (TDFreeCCppResult) dlsym(cryptoengine_lib_handle, "freeCCppResult");
    if (freeFunc == NULL) {
        printf("ERROR: unable to find free  SO function\n");
        cryptoengine_lib_handle=NULL;
        return "";
    }
    (freeFunc)(res);
    return result;
#endif
    return 0;




}

/**
 *  Execute a command on the CryptoEngine, please check the list of available commands in the documentation
 *  convenience function - using less arguments and reusing the config
 *      this function takes a config json as input
  * @param command The Command to be executed: please check the documentation for the list of available commands
  * @param appID The appID from this application, defined by intake of crypto service
  * @param data The data to be treated
  * @param key The key to be used
  * @param authToken The authentication token calculated by the application or BUILD if not applicable
  * @param adminToken The admin token for the application provided by crypto key custodians, or generated during build of the application
  * @param password The password for the admin token
  * @param CA The CA to be used for this operation
  * @param domain The domain (intermediate cert to be used for this operation
  * @param signature The signature which needs to be verified
  * @param uid The unique id of the data (e.g. IV for aes)
  * @return crypto operations return a CCppResult with a string (char*) which contains tags:
  *          - <ERROR>errors generated during processing</ERROR>
  *          - <AUTHENTICATON>the authentication token received from the server, can be used to verify the data coming from the server</AUTHENTICATON>
  *          - <JSON>the json returned from the server, warning this data is in the transport format between client and server (usually base64 encoded) because you need to be able to verify the data within the application</JSON>
     */

string cryptoEngine(json &config,  string command, string &data, string key,  string uid, string signature){ //only to be executed ONCE per process, so all threads should use the same values

    string libname= getValueJson(config, "library", "");
    string rc=cryptoEngine(command,
                           getValueJson(config, "appID", ""),
                           data,
                           key,
                           getValueJson(config, "authToken", ""),
                           getValueJson(config, "adminToken", ""),
                           getValueJson(config, "password", ""),
                           getValueJson(config, "CA", ""),
                           getValueJson(config, "domain", ""),
                           uid,
                           signature,
                           "",
                           "",
                           "",
                           "");
    return rc;




}

/**
 * Execute a file converter oriented command on the CryptoEngine, please check the list of available commands in the documentation, same functionality as cryptoEngine, preferred method if you just want to use the basic file handling
 * CORE Routine for calling the API
 * typical usage
 * - int result =  cryptoEngine("signfile","appID", "data","key","authToken","adminToken", "password", "ca", "domain", "outFile,"errFile", "archiveFile","{\"header\": \"header\", ...}"); // verify  da pkcs file
 * @param command The Command to be executed: please check the documentation for the list of available commands
 * @param appID The appID from this application, defined by intake of crypto service
 * @param data The data (filename) to be treated
 * @param key The key to be used
 * @param authToken The authentication token calculated by the application or BUILD if not applicable
 * @param adminToken The admin token for the application provided by crypto key custodians, or generated during build of the application
 * @param password The password for the admin token
 * @param CA The CA to be used for this operation
 * @param domain The domain (intermediate cert to be used for this operation
 * @param outFile The file result  upon successfull completion
 * @param errFile The file will be moved to the errFile (name) upon failure or it remains at its location if this argument is not specified
 * @param archiveFile Upon successfull completeion te file will be moved to this filename
 * @param keywords json text with keywords {"keyword": "value", ...}, used to specify eventual additional options for the operation
 * @return 0  for successful operation, 1 for verification failures, 2 for technical errors (see logfile for further details)
 */

int cryptoEngineRC(string command, string appID, string data, string key, string authToken,  string adminToken, string password,
                    string CA, string domain, string uid, string signature, string outFile, string errFile, string archiveFile,
                    string keywords){

    tDCryptoEngineRC cryptoEngineRCFunct;
#ifdef _WIN32
    if (cryptoengine_lib_handle == NULL) {
        printf("ERROR: unable to load DLL\n");
        return 1;
    }
    // Get function pointer
    cryptoEngineRCFunct = (tDCryptoEngineRC) GetProcAddress(cryptoengine_lib_handle, "CCppCryptoEngineRC");
    if (cryptoEngineRCFunct == NULL) {
        printf("ERROR: unable to find cryptoengine  DLL function\n");
        FreeLibrary(cryptoengine_lib_handle);
        cryptoengine_lib_handle=NULL;
        return 1;
    }
    int rc =(cryptoEngineRCFunct)(command.c_str(), appID.c_str(),  data.c_str(),  key.c_str(),  authToken.c_str(),   adminToken.c_str(),  password.c_str(),
             CA.c_str(),  domain.c_str(),  uid.c_str(),  signature.c_str(),  outFile.c_str(),  errFile.c_str(),  archiveFile.c_str(),
             keywords.c_str());
    return rc;

#else
    if(cryptoengine_lib_handle==NULL) {
        /* ERROR HANDLING */
        printf("ERROR: unable to load so\n");
        return 1;
    }
    cryptoEngineRCFunct = (tDCryptoEngineRC)
            dlsym(cryptoengine_lib_handle,"CCppCryptoEngineRC");
    if(cryptoEngineRCFunct==NULL) {
        printf("ERROR: unable to find cryptoengine shared libary function\n");
        /* ERROR HANDLING */
    }
    int rc =(*cryptoEngineRCFunct)(command.c_str(), appID.c_str(),  data.c_str(),  key.c_str(),  authToken.c_str(),   adminToken.c_str(),  password.c_str(),
                                          CA.c_str(),  domain.c_str(),  uid.c_str(),  signature.c_str(),  outFile.c_str(),  errFile.c_str(),  archiveFile.c_str(),
                                          keywords.c_str());;

    return rc;
#endif
    return 0;




}

/**
 * Execute a file converter oriented command on the CryptoEngine, please check the list of available commands in the documentation
 * convenience function - using less arguments and reusing the config
 *      this function takes a config json as input
 * typical usage
 * - int result =  cryptoEngine("signfile","appID", "data","key","authToken","adminToken", "password", "ca", "domain", "outFile,"errFile", "archiveFile","{\"header\": \"header\", ...}"); // verify  da pkcs file
 * @param command The Command to be executed: please check the documentation for the list of available commands
 * @param appID The appID from this application, defined by intake of crypto service
 * @param data The data (filename) to be treated
 * @param key The key to be used
 * @param authToken The authentication token calculated by the application or BUILD if not applicable
 * @param adminToken The admin token for the application provided by crypto key custodians, or generated during build of the application
 * @param password The password for the admin token
 * @param CA The CA to be used for this operation
 * @param domain The domain (intermediate cert to be used for this operation
 * @param outFile The file result  upon successfull completion
 * @param errFile The file will be moved to the errFile (name) upon failure or it remains at its location if this argument is not specified
 * @param archiveFile Upon successfull completeion te file will be moved to this filename
 * @return 0  for successfull opertion, 1 for verification failures, 2 for technical errors (see logfile for further details)
 */

int cryptoEngineRC(json &config,  string command, string &data, string key,  string uid, string signature, string outFile, string errFile, string archiveFile){ //only to be executed ONCE per process, so all threads should use the same values

    string libname= getValueJson(config, "library", "");
    int rc=cryptoEngineRC(command,
                          getValueJson(config, "appID", ""),
                          data,
                          key,
                          getValueJson(config, "authToken", ""),
                          getValueJson(config, "adminToken", ""),
                          getValueJson(config, "password", ""),
                          getValueJson(config, "CA", ""),
                          getValueJson(config, "domain", ""),
                          uid,
                          signature,
                          outFile,
                          errFile,
                          archiveFile,
                          "");
    return rc;




}
#endif // CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_HPP