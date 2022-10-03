//
// Created by herwig on 11/10/2021.
//

#ifndef CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_H
#define CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_H


#ifdef __cplusplus
extern "C" {
#endif

struct CCppResult{
  char *string;
  int size=0;
};

#ifdef _WIN32
#define DLLIMPORT __declspec(dllimport)
#else
#define DLLIMPORT
#endif

CCppResult DLLIMPORT * allocateCCppResult(const char *string,int size);

void DLLIMPORT freeCCppResult(CCppResult *cCppResult);
typedef void DLLIMPORT (*TDFreeCCppResult)(CCppResult *);

typedef int DLLIMPORT (*tDCCppInitialize)(const char* , const char*  , const char*  , const char*  , const char*  , const char*  , const char*  );
typedef CCppResult DLLIMPORT * (*tDCryptoEngine)(const char*, const char*, const char*, const char*, const char*,  const char*, const char*,
                             const char*, const char*, const char*, const char*, const char*, const char*, const char*,
                             const char*);
typedef int DLLIMPORT (*tDCryptoEngineRC)(const char*, const char*, const char*, const char*, const char*,  const char*, const char*,
                                      const char*, const char*, const char*, const char*, const char*, const char*, const char*,
                                      const char*);


/////////////controller functions callable from C/Cpp
/**
     * Initializes the vault
     * @param vaultDB Location of vault.db file, preferably use absolute pathnames, it is recommended to put the vault db on local storage, or a ram disk for fast access, in case the initialization fails (consistency check fail) please restore the last known good file
     * @param logFile path of the log file, if not provided, then logging will be disabled, if enable different types of rotating log files will be generated with different extensions (accessLog, serviceLog, log, clientAccessLog, serverCallLog, see logFiles.md for details)
     * @param logLevel level (trace/debug/info/warning/error/fatal) of logging expected in the global log file, usually logging errors is sufficient
     * @param server server to which to connect, can be either separated by colons (to specify different server names only) or sepearated by comma then you can speficy "server:port,server2:port2"
     * @param port port to use for the server
     * @param pillar pillar in which we are running
     * @param keywords json text with keywords {"keyword": "value", ...}, used to specify eventual additional options for the operation
     * @return 0 for successfull execution, 1 for vault consistency check failure, 2 for technical error
     */
// private static native int initialize(String vaultDB, String logFile, String logLevel, String server, Integer port, String pillar, String keywords);
int DLLIMPORT CCppInitialize(const char* vaultDB, const char*  logFile, const char*  logLevel, const char*  server, const char*  port, const char*  pillar, const char*  keywords);

/**
  * Execute a command on the CryptoEngine, please check the list of available commands in the documentation
  * typical usage
  * - String encryptedJson= vaultService.cryptoEngine("encryptPublicRSA","appID", "data","key","authToken","adminToken", "password", "ca", "domain"); // encryption of data with RSA
  * - String decryptedJson= vaultService.cryptoEngine("decryptPrivateRSA","appID", "encryptedData","key","authToken","adminToken", "password", "ca", "domain"); // decryption of data with RSA
  * - String signatureJson= vaultService.cryptoEngine("signRSA","appID", "data","key","authToken","adminToken", "password", "ca", "domain"); // signing of data with RSA
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
CCppResult DLLIMPORT * CCpCryptoEngine(const char* command, const char* appID, const char* data, const char* key, const char* authToken,  const char* adminToken, const char* password,
                         const char* CA, const char* domain, const char* uid, const char* signature, const char* outFile, const char* errFile, const char*archiveFile,
                          const char*keywords);

/**
 * Execute a file converter oriented command on the CryptoEngine, please check the list of available commands in the documentation
 * typical usage
 * - int result =  vaultService.cryptoEngine("signfile","appID", "data","key","authToken","adminToken", "password", "ca", "domain", "outFile,"errFile", "archiveFile","{\"header\": \"header\", ...}"); // verify  da pkcs file
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
 * @return 0  for successfull opertion, 1 for verification failures, 2 for technical errors (see logfile for further details)
 */
//private native String cryptoEngineFile(String command, String appID, String data, String key, String authToken, String adminToken, String password, String CA, String domain, String outFile, String errFile, String archiveFile,  String keywords);

int DLLIMPORT CCpCryptoEngineFile(char* command, char* appID, char* data, char* key, char* authToken,  char* adminToken, char* password,
                 char* CA, char* domain, char* uid, char* signature, char* outFile, char* errFile, char*archiveFile,
                 char*keywords);



#ifdef __cplusplus
}
#endif
#endif // CRYPTONA_APPLICATION_TRANSPORT_PROTECTION_CCPPCLIENTCONTROLLER_H
