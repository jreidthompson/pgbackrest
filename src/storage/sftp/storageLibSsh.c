/***********************************************************************************************************************************
SFTP Storage
***********************************************************************************************************************************/
#include "build.auto.h"

#ifdef HAVE_LIBSSH

#include "common/crypto/hash.h"
#include "common/debug.h"
#include "common/io/fd.h"
#include "common/io/socket/client.h"
#include "common/log.h"
#include "common/regExp.h"
#include "common/user.h"
#include "storage/posix/storage.h"
#include "storage/sftp/readLibSsh.h"
#include "storage/sftp/storage.intern.h"
#include "storage/sftp/writeLibSsh.h"

/***********************************************************************************************************************************
Define PATH_MAX if it is not defined
***********************************************************************************************************************************/
#ifndef PATH_MAX
#define PATH_MAX                                                (4 * 1024)
#endif

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
struct StorageSftp
{
    STORAGE_COMMON_MEMBER;

    IoSession *ioSession;                                           // IoSession (socket) connection to SFTP server
    ssh_session session;                                            // Libssh session
    sftp_session sftpSession;                                       // LibSsh session sftp session
    sftp_file sftpHandle;                                           // Libssh sftp handle
    sftp_dir sftpDir;                                               // Libssh dir handle
    TimeMSec timeout;                                               // Session timeout
    char *fingerprint;                                              // Public key fingerprint hash
};

/***********************************************************************************************************************************
Free libssh resources
***********************************************************************************************************************************/
static void
storageSftpLibSshSessionFreeResource(THIS_VOID)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    // Free the sftp handle
    if (this->sftpHandle != NULL)
    {
        if (sftp_close(this->sftpHandle))
        {
            THROW_FMT(
                ServiceError, "failed to close sftpHandle: %s [%d] sftp error [%d]", ssh_get_error(this->session),
                ssh_get_error_code(this->session), sftp_get_error(this->sftpSession));
        }
    }

    // Free the sftp dir
    if (this->sftpDir != NULL)
    {
        if (sftp_closedir(this->sftpDir))
        {
            THROW_FMT(
                ServiceError,
                "failed to close sftpDir: %s [%d] sftp error [%d]", ssh_get_error(this->session), ssh_get_error_code(this->session),
                sftp_get_error(this->sftpSession));
        }
    }

    // Free the sftp session - this is safe to do even if sftpSession is NULL. This function returns void
    sftp_free(this->sftpSession);

    // Free the ssh session
    if (this->session != NULL)
    {
        // Close the socket
        // Per libssh documentation
        // Note that this function won't close the socket if it was set with ssh_options_set and SSH_OPTIONS_FD. You're
        // responsible for closing the socket. This is new behavior in libssh 0.10.

        close(ioSessionFd(this->ioSession));

        // Close the session and free the session - these functions return void
        ssh_disconnect(this->session);

        // Free the ssh session - this is safe to do even if session is NULL. This function returns void
        ssh_free(this->session);
    }

    ssh_finalize();

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Return a match failed message based on known host check failure type
***********************************************************************************************************************************/
static const char *
storageSftpKnownHostCheckpFailureMsg(const enum ssh_known_hosts_e state, const ssh_session session)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, state);
        FUNCTION_TEST_PARAM_P(VOID, session);
    FUNCTION_TEST_END();

    const char *result;

    switch (state)
    {
        case SSH_KNOWN_HOSTS_CHANGED:
            result = "mismatch in known hosts files: SSH_KNOWN_HOSTS_CHANGED";
            break;

        case SSH_KNOWN_HOSTS_OTHER:
            result = "key type mismatch: SSH_SERVER_OTHER";
            break;

        case SSH_KNOWN_HOSTS_UNKNOWN:
            result = "server is unknown: SSH_KNOWN_HOSTS_UNKNOWN";
            break;

        case SSH_KNOWN_HOSTS_NOT_FOUND:
            result = "could not find known hosts file: SSH_KNOWN_HOSTS_NOT_FOUND";
            break;

        case SSH_KNOWN_HOSTS_ERROR:
            result = ssh_get_error(session);
            break;

        default:
            result = "undefined failure";
            break;
    }

    FUNCTION_TEST_RETURN_CONST(STRINGZ, result);
}

/***********************************************************************************************************************************
Build known hosts file list. If knownHosts is empty build the default file list, otherwise build the list provided. knownHosts
requires full path and/or leading tilde path entries.
***********************************************************************************************************************************/
static StringList *
storageSftpKnownHostsFilesList(const StringList *const knownHosts)
{
    FUNCTION_LOG_BEGIN(logLevelDebug);
        FUNCTION_LOG_PARAM(STRING_LIST, knownHosts);
    FUNCTION_LOG_END();

    StringList *const result = strLstNew();

    MEM_CONTEXT_TEMP_BEGIN()
    {
            // Process the known host list entries and add them to the result list
            for (unsigned int listIdx = 0; listIdx < strLstSize(knownHosts); listIdx++)
            {
                // Get the trimmed file path and add it to the result list
                const String *const filePath = strTrim(strLstGet(knownHosts, listIdx));

                if (strBeginsWithZ(filePath, "~/"))
                {
                    // Replace leading tilde with space, trim space, prepend user home path and add to the result list
                    strLstAddFmt(
                        result, "%s%s", strZ(userHome()), strZ(strTrim(strSub(filePath, (size_t)strChr(filePath, '~') + 1))));
                }
                else
                    strLstAdd(result, filePath);
            }
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(STRING_LIST, result);
}

/***********************************************************************************************************************************
Attempt to verify the host key using libssh default known hosts files (~/.ssh/known_hosts and /etc/ssh/ssh_known_hosts)
***********************************************************************************************************************************/
static void
verify_knownhost(ssh_session session, const StringList *const knownHosts, StringId hostKeyCheckType, const String *const host)
{
    FUNCTION_LOG_BEGIN(logLevelDebug);
        FUNCTION_LOG_PARAM_P(VOID, session);
        FUNCTION_LOG_PARAM(STRING_LIST, knownHosts);
        FUNCTION_LOG_PARAM(STRING_ID, hostKeyCheckType);
        FUNCTION_LOG_PARAM(STRING, host);
    FUNCTION_LOG_END();

    ASSERT(session != NULL);

    enum ssh_known_hosts_e state = SSH_KNOWN_HOSTS_UNKNOWN;
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < SSH_OK)
    {
        ssh_disconnect(session);

        // Free the ssh session - this is safe to do even if session is NULL. This function returns void
        ssh_free(session);
        THROW_FMT(ServiceError, "unable to get server public key");
    }

    rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen);
    SSH_KEY_FREE(srv_pubkey);
    if (rc < SSH_OK)
    {
        ssh_disconnect(session);

        // Free the ssh session - this is safe to do even if session is NULL. This function returns void
        ssh_free(session);
        THROW_FMT(ServiceError, "unable to get public key hash");
    }

    // Flag to restore the default known hosts files if we overwrite them
    bool restoreDefaultKNownHosts = false;

    if (strLstEmpty(knownHosts))
    {
        enum ssh_known_hosts_e old_state;

        // Check default known hosts files for known hosts
        LOG_DETAIL_FMT("Check default locations ~/.ssh/known_hosts and /etc/ssh/ssh_known_hosts for known hosts: '%s'", strZ(host));

        old_state = state = ssh_session_is_known_server(session);

        LOG_DETAIL_FMT("Primary known hosts files state: '%d'", state);

        if (state != SSH_KNOWN_HOSTS_OK)
        {
            restoreDefaultKNownHosts = true;

            LOG_DETAIL_FMT(
                "Check default locations ~/.ssh/known_hosts2 and /etc/ssh/ssh_known_hosts2 for known hosts: '%s'", strZ(host));

            // Check the secondary set of default known hosts files
            if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "%%d/.ssh/known_hosts2") != SSH_OK)
            {
                ssh_disconnect(session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(session);
                THROW_FMT(ServiceError, "unable to set '~/.ssh/known_hosts2' known hosts file: %s", ssh_get_error(session));
            }

            if (ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/etc/ssh/ssh_known_hosts2") != SSH_OK)
            {
                ssh_disconnect(session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(session);
                THROW_FMT(ServiceError, "unable to set '/etc/ssh/ssh_known_hosts2' known hosts file: %s", ssh_get_error(session));
            }

            state = ssh_session_is_known_server(session);

            LOG_DETAIL_FMT("Secondary known hosts files state: '%d'", state);

            // If host is unknown or the hosts file does not exist then restore the original state otherwise return the new state
            if (state == SSH_KNOWN_HOSTS_UNKNOWN || state == SSH_KNOWN_HOSTS_NOT_FOUND)
                state = old_state;
        }
    }
    else
    {
        restoreDefaultKNownHosts = true;

        // Check for a verified host key by overriding the default known hosts file with those in the provided list

        MEM_CONTEXT_TEMP_BEGIN()
        {
            // Get the list of known host files to search
            const StringList *const knownHostsPathList = storageSftpKnownHostsFilesList(knownHosts);

            // Loop through the known hosts list checking each for a match
            for (unsigned int listIdx = 0; listIdx < strLstSize(knownHostsPathList); listIdx++)
            {
                const String *const knownHostsPath = strLstGet(knownHostsPathList, listIdx);

                // Set the known hosts file to the current list entry
                if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, strZ(knownHostsPath)) != SSH_OK)
                {
                    ssh_disconnect(session);

                    // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                    ssh_free(session);
                    THROW_FMT(ServiceError, "unable to set known hosts file: %s", ssh_get_error(session));
                }

                state = ssh_session_is_known_server(session);

                // If a match is found then break out of the loop
                if (state == SSH_KNOWN_HOSTS_OK)
                    break;

                LOG_DETAIL_FMT("No match in user provided known hosts file '%s' state: '%d'", strZ(knownHostsPath), state);
            }
        }
        MEM_CONTEXT_TEMP_END();
    }

    if (restoreDefaultKNownHosts)
    {
        // Restore the local and global known hosts file to the defaults
        if (ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, NULL) != SSH_OK)
        {
            ssh_disconnect(session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(session);
            THROW_FMT(ServiceError, "unable to reset default known hosts file: %s", ssh_get_error(session));
        }

        if (ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, NULL) != SSH_OK)
        {
            ssh_disconnect(session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(session);
            THROW_FMT(ServiceError, "unable to reset default global known hosts file: %s", ssh_get_error(session));
        }
    }

    if (state != SSH_KNOWN_HOSTS_OK)
    {
        MEM_CONTEXT_TEMP_BEGIN()
        {
            const String *const hostKeyCheckTypeStr = strIdToStr(hostKeyCheckType);

            // Handle failure to match in a similar manner as ssh_config StrictHostKeyChecking. If this flag is set to
            // "strict", never automatically add host keys to the ~/.ssh/known_hosts file, and refuse to connect to hosts
            // whose host key has changed. This option forces the user to manually add all new hosts. If this flag is set to
            // "accept-new" then automatically add new host keys to the user known hosts files, but do not permit
            // connections to hosts with changed host keys.
            switch (hostKeyCheckType)
            {
                case SFTP_STRICT_HOSTKEY_CHECKING_STRICT:
                {
                    ssh_disconnect(session);

                    // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                    ssh_free(session);

                    // Throw an error when set to strict and we have any result other than match
                    THROW_FMT(
                        ServiceError, "known hosts failure: '%s': %s [%d]: check type [%s]", strZ(host),
                        storageSftpKnownHostCheckpFailureMsg(state, session), state, strZ(hostKeyCheckTypeStr));
                    break;
                }

                default:
                {
                    ASSERT(hostKeyCheckType == SFTP_STRICT_HOSTKEY_CHECKING_ACCEPT_NEW);

                    // Throw an error when set to accept-new and match fails or mismatches else add the new host key to the
                    // user's known_hosts file
                    if (state == SSH_KNOWN_HOSTS_CHANGED || state == SSH_KNOWN_HOSTS_ERROR)
                    {
                        ssh_disconnect(session);

                        // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                        ssh_free(session);
                        THROW_FMT(
                            ServiceError, "known hosts failure: '%s': %s [%d]: check type [%s]", strZ(host),
                            storageSftpKnownHostCheckpFailureMsg(state, session), state, strZ(hostKeyCheckTypeStr));
                    }
                    else
                    {
                        LOG_WARN_FMT(
                            "host '%s' not found in known hosts files, attempting to add host to '~/.ssh/known_hosts'", strZ(host));

                        // Add the new host key to the user's known_hosts file
                        if (ssh_session_update_known_hosts(session) != SSH_OK)
                        {
                            LOG_WARN_FMT(
                                "ssh_session_update_known_hosts failed for: '%s': %s: state [%d]: check type [%s]", strZ(host),
                                ssh_get_error(session), state, strZ(hostKeyCheckTypeStr));
                        }
                        else
                            LOG_WARN_FMT(PROJECT_NAME " added new host '%s' to '~/.ssh/known_hosts'", strZ(host));
                    }
                    break;
                }
            }
        }
        MEM_CONTEXT_TEMP_END();
    }


//    switch(state)
//    {
//        case SSH_KNOWN_HOSTS_CHANGED:
//            fprintf(stderr,"Host key for server changed : server's one is now :\n");
//            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
//            ssh_clean_pubkey_hash(&hash);
//            fprintf(stderr,"For security reason, connection will be stopped\n");
//            result = SSH_ERROR;
//            //return -1;
//        case SSH_KNOWN_HOSTS_OTHER:
//            fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
//            fprintf(stderr,"An attacker might change the default server key to confuse your client"
//                    "into thinking the key does not exist\n"
//                    "We advise you to rerun the client with -d or -r for more safety.\n");
//            result = SSH_ERROR;
//            //return -1;
//        case SSH_KNOWN_HOSTS_NOT_FOUND:
//            fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
//            fprintf(stderr,"the file will be automatically created.\n");
//            /* fallback to SSH_SERVER_NOT_KNOWN behavior */
//        case SSH_SERVER_NOT_KNOWN:
//            fprintf(stderr,
//                    "The server is unknown. Do you trust the host key (yes/no)?\n");
//            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
//
//            if (fgets(buf, sizeof(buf), stdin) == NULL) {
//                ssh_clean_pubkey_hash(&hash);
//                result = SSH_ERROR;
//                //return -1;
//            }
//            //        if(strncasecmp(buf,"yes",3)!=0){
//            //            ssh_clean_pubkey_hash(&hash);
//            //            //return -1;
//            //        }
//            fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
//            if (fgets(buf, sizeof(buf), stdin) == NULL) {
//                ssh_clean_pubkey_hash(&hash);
//                result = SSH_ERROR;
//                //return -1;
//            }
//            //        if(strncasecmp(buf,"yes",3)==0){
//            //            rc = ssh_session_update_known_hosts(session);
//            //            if (rc != SSH_OK) {
//            //                ssh_clean_pubkey_hash(&hash);
//            //                fprintf(stderr, "error %s\n", strerror(errno));
//            //                //return -1;
//            //            }
//            //        }
//
//            break;
//        case SSH_KNOWN_HOSTS_ERROR:
//            ssh_clean_pubkey_hash(&hash);
//            fprintf(stderr,"%s",ssh_get_error(session));
//            result = SSH_ERROR;
//            //return -1;
//        case SSH_KNOWN_HOSTS_OK:
//            break; /* ok */
//    }

    ssh_clean_pubkey_hash(&hash);

    FUNCTION_LOG_RETURN_VOID();
}

///***********************************************************************************************************************************
//Return known host key type based on host key type
//***********************************************************************************************************************************/
//static int
//storageSftpKnownHostKeyType(const int hostKeyType)
//{
//    FUNCTION_TEST_BEGIN();
//        FUNCTION_TEST_PARAM(INT, hostKeyType);
//    FUNCTION_TEST_END();
//
//    int result;
//
//    switch (hostKeyType)
//    {
//        case LIBSSH2_HOSTKEY_TYPE_RSA:
//            result = LIBSSH2_KNOWNHOST_KEY_SSHRSA;
//            break;
//
//        case LIBSSH2_HOSTKEY_TYPE_DSS:
//            result = LIBSSH2_KNOWNHOST_KEY_SSHDSS;
//            break;
//
//#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_256
//        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
//            result = LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
//            break;
//#endif
//
//#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_384
//        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
//            result = LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
//            break;
//#endif
//
//#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_521
//        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
//            result = LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
//            break;
//#endif
//
//#ifdef LIBSSH2_HOSTKEY_TYPE_ED25519
//        case LIBSSH2_HOSTKEY_TYPE_ED25519:
//            result = LIBSSH2_KNOWNHOST_KEY_ED25519;
//            break;
//#endif
//
//        default:
//            result = 0;
//            break;
//    }
//
//    FUNCTION_TEST_RETURN(INT, result);
//}
//

///**********************************************************************************************************************************/
//static String *
//storageSftpLibSsh2SessionLastError(LIBSSH2_SESSION *const libSsh2Session)
//{
//    FUNCTION_TEST_BEGIN();
//        FUNCTION_TEST_PARAM_P(VOID, libSsh2Session);
//    FUNCTION_TEST_END();
//
//    String *result;
//    char *libSsh2ErrMsg;
//    int libSsh2ErrMsgLen;
//
//    const int rc = libssh2_session_last_error(libSsh2Session, &libSsh2ErrMsg, &libSsh2ErrMsgLen, 0);
//
//    if (libSsh2ErrMsgLen != 0)
//        result = strNewZN(libSsh2ErrMsg, (size_t)libSsh2ErrMsgLen);
//    else
//        result = strNewFmt("libssh2 no session error message provided [%d]", rc);
//
//    FUNCTION_TEST_RETURN(STRING, result);
//}

/***********************************************************************************************************************************
Rewrite the user's known_hosts file with a new entry
***********************************************************************************************************************************/
//static void
//storageSftpUpdateKnownHostsFile(
//    StorageSftp *const this, const int hostKeyType, const String *const host, const char *const hostKey, const size_t hostKeyLen)
//{
//    FUNCTION_LOG_BEGIN(logLevelDebug);
//        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
//        FUNCTION_LOG_PARAM(INT, hostKeyType);
//        FUNCTION_LOG_PARAM(STRING, host);
//        FUNCTION_LOG_PARAM(STRINGZ, hostKey);
//        FUNCTION_LOG_PARAM(SIZE, hostKeyLen);
//    FUNCTION_LOG_END();
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        //int rc;
//
////        // Init a known host collection for the user's known_hosts file
////        const char *const userKnownHostsFile = strZ(strNewFmt("%s%s", strZ(userHome()), "/.ssh/known_hosts"));
////        LIBSSH2_KNOWNHOSTS *const userKnownHostsList = libssh2_knownhost_init(this->session);
////
////        LOG_WARN_FMT("host '%s' not found in known hosts files, attempting to add host to '%s'", strZ(host), userKnownHostsFile);
////
////        if (userKnownHostsList == NULL)
////        {
////            // Get the libssh2 error message and emit warning
////            const int rc = libssh2_session_last_errno(this->session);
////            LOG_WARN_FMT(
////                "libssh2_knownhost_init failed for '%s' for update: libssh2 errno [%d] %s", userKnownHostsFile, rc,
////                strZ(storageSftpLibSsh2SessionLastError(this->session)));
////        }
////        else
////        {
////            // Read the user's known_hosts file entries into the collection. libssh2_knownhost_readfile() returns the number of
////            // successfully loaded hosts or a negative value on error, an empty known hosts file will return 0.
////            if ((rc = libssh2_knownhost_readfile(userKnownHostsList, userKnownHostsFile, LIBSSH2_KNOWNHOST_FILE_OPENSSH)) < 0)
////            {
////                // Missing known_hosts file will return LIBSSH2_ERROR_FILE. Possibly issues other than missing may return this.
////                if (rc == LIBSSH2_ERROR_FILE)
////                {
////                    // If user's known_hosts file is non-existant, create an empty one for libssh2 to operate on
////                    const Storage *const sshStorage =
////                        storagePosixNewP(
////                            strNewFmt("%s%s", strZ(userHome()), "/.ssh"), .modeFile = 0600, .modePath = 0700, .write = true);
////
////                    if (!storageExistsP(sshStorage, strNewFmt("%s", "known_hosts")))
////                        storagePutP(storageNewWriteP(sshStorage, strNewFmt("%s", "known_hosts")), NULL);
////
////                    // Try to load the user's known_hosts file entries into the collection again
////                    rc = libssh2_knownhost_readfile(userKnownHostsList, userKnownHostsFile, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
////                }
////            }
////
////            // If the user's known_hosts file was read successfully, add the host to the collection and rewrite the file
////            if (rc >= 0)
////            {
////                // Check for a supported known host key type
////                const int knownHostKeyType = storageSftpKnownHostKeyType(hostKeyType);
////
////                if (knownHostKeyType != 0)
////                {
////                    // Add host to the internal list
////                    if (libssh2_knownhost_addc(
////                            userKnownHostsList, strZ(host), NULL, hostKey, hostKeyLen,
////                            strZ(strNewZ("Generated from " PROJECT_NAME)), strlen(strZ(strNewZ("Generated from " PROJECT_NAME))),
////                            LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | knownHostKeyType, NULL) == 0)
////                    {
////                        // Rewrite the updated known_hosts file
////                        rc = libssh2_knownhost_writefile(userKnownHostsList, userKnownHostsFile, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
////
////                        if (rc != 0)
////                            LOG_WARN_FMT(PROJECT_NAME " unable to write '%s' for update", userKnownHostsFile);
////                        else
////                            LOG_WARN_FMT(PROJECT_NAME " added new host '%s' to '%s'", strZ(host), userKnownHostsFile);
////                    }
////                    else
////                        LOG_WARN_FMT(PROJECT_NAME " failed to add '%s' to known_hosts internal list", strZ(host));
////                }
////                else
////                    LOG_WARN_FMT("unsupported key type [%d], unable to update knownhosts for '%s'", hostKeyType, strZ(host));
////            }
////            else
////            {
////                // On readfile failure warn that we're unable to update the user's known_hosts file
////                LOG_WARN_FMT(
////                    "libssh2 unable to read '%s' for update: libssh2 errno [%d] %s\n"
////                    "HINT: does '%s' exist with proper permissions?", userKnownHostsFile, rc,
////                    strZ(storageSftpLibSsh2SessionLastError(this->session)), userKnownHostsFile);
////            }
////        }
////
////        // Free the user's known hosts list
////        if (userKnownHostsList)
////            libssh2_knownhost_free(userKnownHostsList);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    FUNCTION_LOG_RETURN_VOID();
//}

///**********************************************************************************************************************************/
//FN_EXTERN FN_NO_RETURN void
//storageSftpEvalLibSsh2Error(
//    const int ssh2Errno, const uint64_t sftpErrno, const ErrorType *const errorType, const String *const message,
//    const String *const hint)
//{
//    FUNCTION_TEST_BEGIN();
//        FUNCTION_TEST_PARAM(INT, ssh2Errno);
//        FUNCTION_TEST_PARAM(UINT64, sftpErrno);
//        FUNCTION_TEST_PARAM(ERROR_TYPE, errorType);
//        FUNCTION_TEST_PARAM(STRING, message);
//        FUNCTION_TEST_PARAM(STRING, hint);
//    FUNCTION_TEST_END();
//
//    ASSERT(errorType != NULL);
//
//    THROWP_FMT(
//        errorType, "%s%s%s%s", message != NULL ? zNewFmt("%s%s", strZ(message), ssh2Errno == 0 ? "" : ": ") : "",
//        ssh2Errno == 0 ? "" : zNewFmt("libssh2 error [%d]", ssh2Errno),
//        ssh2Errno == LIBSSH2_ERROR_SFTP_PROTOCOL ? zNewFmt(": sftp error [%" PRIu64 "]", sftpErrno) : "",
//        hint != NULL ? zNewFmt("\n%s", strZ(hint)) : "");
//
//    FUNCTION_TEST_NO_RETURN();
//}

/***********************************************************************************************************************************
Call in a loop whenever a libssh2 call might return LIBSSH2_ERROR_EAGAIN. We handle checking the rc from the libssh2 call here and
will immediately exit out if it isn't LIBSSH2_ERROR_EAGAIN.

Note that LIBSSH2_ERROR_EAGAIN can still be set after this call -- if that happens then there was a timeout while waiting for the fd
to be ready.
***********************************************************************************************************************************/
FN_EXTERN bool
storageSftpWaitFd(StorageSftp *const this, const int64_t rc)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STORAGE_SFTP, this);
        FUNCTION_TEST_PARAM(INT64, rc);
    FUNCTION_TEST_END();

    if (rc != SSH_AGAIN)
        FUNCTION_TEST_RETURN(BOOL, false);

    const int direction = ssh_get_poll_flags(this->session);
    const bool waitingRead = direction & SSH_READ_PENDING;
    const bool waitingWrite = direction & SSH_WRITE_PENDING;

    if (!waitingRead && !waitingWrite)
        FUNCTION_TEST_RETURN(BOOL, true);

    FUNCTION_TEST_RETURN(BOOL, fdReady(ioSessionFd(this->ioSession), waitingRead, waitingWrite, this->timeout));
}

///**********************************************************************************************************************************/
//static bool
//storageSftpLibSsh2FxNoSuchFile(THIS_VOID, const int rc)
//{
//    THIS(StorageSftp);
//
//    FUNCTION_TEST_BEGIN();
//        FUNCTION_TEST_PARAM(STORAGE_SFTP, this);
//        FUNCTION_TEST_PARAM(INT, rc);
//    FUNCTION_TEST_END();
//
//    ASSERT(this != NULL);
//
//    FUNCTION_TEST_RETURN(
//        BOOL, rc == LIBSSH2_ERROR_SFTP_PROTOCOL && libssh2_sftp_last_error(this->sftpSession) == LIBSSH2_FX_NO_SUCH_FILE);
//}

/**********************************************************************************************************************************/
static StorageInfo
storageSftpInfo(THIS_VOID, const String *const file, const StorageInfoLevel level, const StorageInterfaceInfoParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, file);
        FUNCTION_LOG_PARAM(ENUM, level);
        FUNCTION_LOG_PARAM(BOOL, param.followLink);
    FUNCTION_LOG_END();

    FUNCTION_AUDIT_STRUCT();

    ASSERT(this != NULL);
    ASSERT(file != NULL);

    StorageInfo result = {.level = level};

    // Stat the file to check if it exists
    sftp_attributes attr;
    int rc;

    if (param.followLink)
        attr = sftp_stat(this->sftpSession, strZ(file));
    else
        attr = sftp_lstat(this->sftpSession, strZ(file));

    if (attr == NULL)
    {
        // Throw on errors other than no such file
        if ((rc = sftp_get_error(this->sftpSession)) != SSH_FX_NO_SUCH_FILE)
        {

            THROW_FMT(
                FileOpenError,
                STORAGE_ERROR_INFO ": %s", strZ(file),
                strZ(strNewFmt("%s libssh err [%d] sftp err [%d]",
                        ssh_get_error(this->session), ssh_get_error_code(this->session), rc)));
        }
    }
    else
    {
        result.exists = true;

        // Add type info (no need set file type since it is the default)
        if (result.level >= storageInfoLevelType && !S_ISREG(attr->permissions))
        {
            if (S_ISDIR(attr->permissions))
                result.type = storageTypePath;
            else if (S_ISLNK(attr->permissions))
                result.type = storageTypeLink;
            else
                result.type = storageTypeSpecial;
        }

        // Add basic level info
        if (result.level >= storageInfoLevelBasic)
        {
            if (attr->flags & SSH_FILEXFER_ATTR_ACMODTIME)
                result.timeModified = (time_t)attr->mtime64;

            if (result.type == storageTypeFile)
                if (attr->flags & SSH_FILEXFER_ATTR_SIZE)
                    result.size = (uint64_t)attr->size;
        }

        // Add detail level info
        if (result.level >= storageInfoLevelDetail)
        {
            if (attr->flags & SSH_FILEXFER_ATTR_UIDGID)
            {
                result.groupId = (unsigned int)attr->gid;
                result.userId = (unsigned int)attr->uid;
            }

            if (attr->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
                result.mode = attr->permissions & (S_IRWXU | S_IRWXG | S_IRWXO);

            if (result.type == storageTypeLink)
            {
                // Get the destination of the link
                char *linkDestination = sftp_readlink(this->sftpSession, strZ(file));

                if (linkDestination== NULL)
                {
                    // Free the attributes. This is safe to do even if attr is NULL.
                    sftp_attributes_free(attr);

                    THROW_FMT(
                        FileReadError,
                        "unable to get destination for link '%s': %s", strZ(file),
                        strZ(
                            strNewFmt("%s [%d]: sftp error [%d]", ssh_get_error(this->session), ssh_get_error_code(this->session),
                                sftp_get_error(this->sftpSession))));
                }

                // Stat the link destination to get the size
                const sftp_attributes destAttr = sftp_stat(this->sftpSession, linkDestination);
                if (destAttr == NULL)
                {
                    // Free the linkDestination
                    SSH_STRING_FREE_CHAR(linkDestination);

                    THROW_FMT(
                        FileReadError,
                        "unable to get file size for link destination '%s': %s", strZ(file),
                        strZ(
                            strNewFmt("%s [%d]: sftp error [%d]", ssh_get_error(this->session), ssh_get_error_code(this->session),
                                sftp_get_error(this->sftpSession))));
                }

                // Set the link destination and size of link destination as the file size
                result.size = (uint64_t)destAttr->size;

                MEM_CONTEXT_TEMP_BEGIN()
                {
                    String *resultStr = strNewZN(linkDestination, strlen(linkDestination));

                    MEM_CONTEXT_PRIOR_BEGIN()
                    {
                        result.linkDestination = strDup(resultStr);
                    }
                    MEM_CONTEXT_PRIOR_END();
                }
                MEM_CONTEXT_TEMP_END();

                // Free the linkDestination
                SSH_STRING_FREE_CHAR(linkDestination);

                // Free the attributes. This is safe to do even if attr is NULL.
                sftp_attributes_free(destAttr);
            }
        }
    }



//    // Stat the file to check if it exists
//    LIBSSH2_SFTP_ATTRIBUTES attr;
//    int rc;
//
//    do
//    {
//        rc = libssh2_sftp_stat_ex(
//            this->sftpSession, strZ(file), (unsigned int)strSize(file), param.followLink ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT,
//            &attr);
//    }
//    while (storageSftpWaitFd(this, rc));
//
//    if (rc != 0)
//    {
//        if (rc == LIBSSH2_ERROR_EAGAIN)
//            THROW_FMT(FileOpenError, "timeout opening '%s'", strZ(file));
//
//        // Throw libssh2 on errors other than no such file
//        if (!storageSftpLibSsh2FxNoSuchFile(this, rc))
//        {
//            storageSftpEvalLibSsh2Error(
//                rc, libssh2_sftp_last_error(this->sftpSession), &FileOpenError, strNewFmt(STORAGE_ERROR_INFO, strZ(file)), NULL);
//        }
//    }
//    // Else the file exists
//    else
//    {
//        result.exists = true;
//
//        // Add type info (no need set file type since it is the default)
//        if (result.level >= storageInfoLevelType && !LIBSSH2_SFTP_S_ISREG(attr.permissions))
//        {
//            if (LIBSSH2_SFTP_S_ISDIR(attr.permissions))
//                result.type = storageTypePath;
//            else if (LIBSSH2_SFTP_S_ISLNK(attr.permissions))
//                result.type = storageTypeLink;
//            else
//                result.type = storageTypeSpecial;
//        }
//
//        // Add basic level info
//        if (result.level >= storageInfoLevelBasic)
//        {
//            if ((attr.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) != 0)
//                result.timeModified = (time_t)attr.mtime;
//
//            if (result.type == storageTypeFile)
//                if ((attr.flags & LIBSSH2_SFTP_ATTR_SIZE) != 0)
//                    result.size = (uint64_t)attr.filesize;
//        }
//
//        // Add detail level info
//        if (result.level >= storageInfoLevelDetail)
//        {
//            if ((attr.flags & LIBSSH2_SFTP_ATTR_UIDGID) != 0)
//            {
//                result.groupId = (unsigned int)attr.gid;
//                result.userId = (unsigned int)attr.uid;
//            }
//
//            if ((attr.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0)
//                result.mode = attr.permissions & (LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO);
//
//            if (result.type == storageTypeLink)
//            {
//                char linkDestination[PATH_MAX] = {0};
//                ssize_t linkDestinationSize = 0;
//
//                do
//                {
//                    linkDestinationSize = libssh2_sftp_symlink_ex(
//                        this->sftpSession, strZ(file), (unsigned int)strSize(file), linkDestination, PATH_MAX - 1,
//                        LIBSSH2_SFTP_READLINK);
//                }
//                while (storageSftpWaitFd(this, linkDestinationSize));
//
//                if (linkDestinationSize == LIBSSH2_ERROR_EAGAIN)
//                    THROW_FMT(FileReadError, "timeout getting destination for link '%s'", strZ(file));
//
//                if (linkDestinationSize < 0)
//                {
//                    storageSftpEvalLibSsh2Error(
//                        (int)linkDestinationSize, libssh2_sftp_last_error(this->sftpSession), &FileReadError,
//                        strNewFmt("unable to get destination for link '%s'", strZ(file)), NULL);
//                }
//
//                result.linkDestination = strNewZN(linkDestination, (size_t)linkDestinationSize);
//            }
//        }
//    }
//
    // Free the attributes. This is safe to do even if attr is NULL.
    sftp_attributes_free(attr);

    FUNCTION_LOG_RETURN(STORAGE_INFO, result);
}

/**********************************************************************************************************************************/
static String *
storageSftpExpandTildePath(const String *const tildePath)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, tildePath);
    FUNCTION_TEST_END();

    String *const result = strNew();

    // Append to user home directory path substring after the tilde
    MEM_CONTEXT_TEMP_BEGIN()
    {
        strCatFmt(result, "%s%s", strZ(userHome()), strZ(strSub(tildePath, (size_t)strChr(tildePath, '~') + 1)));
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(STRING, result);
}

/**********************************************************************************************************************************/
// Helper function to get info for a file if it exists. This logic can't live directly in storageSftpList() because there is a race
// condition where a file might exist while listing the directory but it is gone before stat() can be called. In order to get
// complete test coverage this function must be split out.
static void
storageSftpListEntry(
    StorageSftp *const this, StorageList *const list, const String *const path, const char *const name,
    const StorageInfoLevel level)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STORAGE_SFTP, this);
        FUNCTION_TEST_PARAM(STORAGE_LIST, list);
        FUNCTION_TEST_PARAM(STRING, path);
        FUNCTION_TEST_PARAM(STRINGZ, name);
        FUNCTION_TEST_PARAM(ENUM, level);
    FUNCTION_TEST_END();

    FUNCTION_AUDIT_HELPER();

    ASSERT(this != NULL);
    ASSERT(list != NULL);
    ASSERT(path != NULL);
    ASSERT(name != NULL);

    StorageInfo info = storageInterfaceInfoP(this, strNewFmt("%s/%s", strZ(path), name), level);

    if (info.exists)
    {
        info.name = STR(name);
        storageLstAdd(list, &info);
    }

    FUNCTION_TEST_RETURN_VOID();
}

static StorageList *
storageSftpList(THIS_VOID, const String *const path, const StorageInfoLevel level, const StorageInterfaceListParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, path);
        FUNCTION_LOG_PARAM(ENUM, level);
        (void)param;                                                // No parameters are used
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(path != NULL);

    StorageList *result = NULL;

    // Open the directory for read
    sftp_dir dir = sftp_opendir(this->sftpSession, strZ(path));
    if (dir == NULL)
    {
        // Throw on errors other than no such file
        int rc = sftp_get_error(this->sftpSession);
        if (rc != SSH_FX_NO_SUCH_FILE)
        {
            THROW_FMT(
                PathOpenError,
                STORAGE_ERROR_LIST_INFO ": %s", strZ(path),
                strZ(strNewFmt("%s libssh err [%d] sftp err [%d]",
                        ssh_get_error(this->session), ssh_get_error_code(this->session), rc)));
        }
    }
    else
    {
        // Directory was found
        result = storageLstNew(level);

//        TRY_BEGIN()
//        {
            MEM_CONTEXT_TEMP_RESET_BEGIN()
            {
                // Read the directory entries
                sftp_attributes attr;

                while ((attr = sftp_readdir(this->sftpSession, dir)) != NULL)
                {
                    // Always skip . and ..
                    if (!strEqZ(DOT_STR, attr->name) && !strEqZ(DOTDOT_STR, attr->name))
                    {
                        if (level == storageInfoLevelExists)
                        {
                            const StorageInfo storageInfo =
                            {
                                .name = STR(attr->name),
                                .level = storageInfoLevelExists,
                                .exists = true,
                            };

                            storageLstAdd(result, &storageInfo);
                        }
                        else
                            storageSftpListEntry(this, result, path, attr->name, level);
                    }

                    // Free the attributes. This is safe to do even if attr is NULL.
                    sftp_attributes_free(attr);

                    // Reset the memory context occasionally so we don't use too much memory or slow down processing
                    MEM_CONTEXT_TEMP_RESET(1000);
                }
                if (!sftp_dir_eof(dir))
                {
                    // Close the directory
                    (void)sftp_closedir(dir);

                    THROW_FMT(
                        FileReadError,
                        "unable to read directory '%s' %s", strZ(path),
                        strZ(strNewFmt("%s libssh err [%d] sftp err [%d]", ssh_get_error(this->session),
                                ssh_get_error_code(this->session), sftp_get_error(this->sftpSession))));
                }

                // Close the directory
                int rc = sftp_closedir(dir);
                if (rc != SSH_NO_ERROR)
                {
                    THROW_FMT(
                        PathCloseError,
                        "unable to close directory '%s' %s", strZ(path),
                        strZ(strNewFmt("%s libssh err [%d] sftp err [%d]", ssh_get_error(this->session),
                                ssh_get_error_code(this->session), sftp_get_error(this->sftpSession))));
                }

            }
            MEM_CONTEXT_TEMP_END();
//        }
//        FINALLY()
//        {
//                fprintf(stderr, "close dir\n");
//                fflush(stderr);
//            // Close the directory
//            sftp_closedir(dir);
//        }
//        TRY_END();
    }



    // Open the directory for read
//    LIBSSH2_SFTP_HANDLE *sftpHandle;
//
//    do
//    {
//        sftpHandle = libssh2_sftp_open_ex(this->sftpSession, strZ(path), (unsigned int)strSize(path), 0, 0, LIBSSH2_SFTP_OPENDIR);
//    }
//    while (sftpHandle == NULL && storageSftpWaitFd(this, libssh2_session_last_errno(this->session)));
//
//    // If the directory could not be opened process errors and report missing directories
//    if (sftpHandle == NULL)
//    {
//        const int rc = libssh2_session_last_errno(this->session);
//
//        if (rc == LIBSSH2_ERROR_EAGAIN)
//            THROW_FMT(FileReadError, "timeout opening directory '%s'", strZ(path));
//
//        // If sftpHandle == NULL is due to LIBSSH2_FX_NO_SUCH_FILE, do not throw error here, return NULL result
//        if (!storageSftpLibSsh2FxNoSuchFile(this, rc))
//        {
//            storageSftpEvalLibSsh2Error(
//                rc, libssh2_sftp_last_error(this->sftpSession), &PathOpenError, strNewFmt(STORAGE_ERROR_LIST_INFO, strZ(path)),
//                NULL);
//        }
//    }
//    else
//    {
//        // Directory was found
//        result = storageLstNew(level);
//
//        TRY_BEGIN()
//        {
//            MEM_CONTEXT_TEMP_RESET_BEGIN()
//            {
//                LIBSSH2_SFTP_ATTRIBUTES attr;
//                char filename[PATH_MAX] = {0};
//                int len;
//
//                // Read the directory entries
//                do
//                {
//                    len = libssh2_sftp_readdir_ex(sftpHandle, filename, PATH_MAX - 1, NULL, 0, &attr);
//
//                    if (len > 0)
//                    {
//                        filename[len] = '\0';
//
//                        // Always skip . and ..
//                        if (!strEqZ(DOT_STR, filename) && !strEqZ(DOTDOT_STR, filename))
//                        {
//                            if (level == storageInfoLevelExists)
//                            {
//                                const StorageInfo storageInfo =
//                                {
//                                    .name = STR(filename),
//                                    .level = storageInfoLevelExists,
//                                    .exists = true,
//                                };
//
//                                storageLstAdd(result, &storageInfo);
//                            }
//                            else
//                                storageSftpListEntry(this, result, path, filename, level);
//                        }
//
//                        // Reset the memory context occasionally so we don't use too much memory or slow down processing
//                        MEM_CONTEXT_TEMP_RESET(1000);
//                    }
//                }
//                while (len > 0 || storageSftpWaitFd(this, len));
//            }
//            MEM_CONTEXT_TEMP_END();
//        }
//        FINALLY()
//        {
//            int rc;
//
//            do
//            {
//                rc = libssh2_sftp_closedir(sftpHandle);
//            }
//            while (storageSftpWaitFd(this, rc));
//
//            if (rc != 0)
//            {
//                if (rc != LIBSSH2_ERROR_EAGAIN)
//                {
//                    storageSftpEvalLibSsh2Error(
//                        rc, libssh2_sftp_last_error(this->sftpSession), &PathCloseError,
//                        strNewFmt("unable to close path '%s' after listing", strZ(path)), NULL);
//                }
//                else
//                    THROW_FMT(PathCloseError, "timeout closing path '%s' after listing", strZ(path));
//            }
//
//            sftpHandle = NULL;
//        }
//        TRY_END();
//    }

    FUNCTION_LOG_RETURN(STORAGE_LIST, result);
}

/**********************************************************************************************************************************/
static void
storageSftpRemove(THIS_VOID, const String *const file, const StorageInterfaceRemoveParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, file);
        FUNCTION_LOG_PARAM(BOOL, param.errorOnMissing);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(file != NULL);

    // Attempt to unlink the file
    //int rc;

//    do
//    {
//        rc = libssh2_sftp_unlink_ex(this->sftpSession, strZ(file), (unsigned int)strSize(file));
//    }
//    while (storageSftpWaitFd(this, rc));
//
//    if (rc != 0)
//    {
//        if (rc == LIBSSH2_ERROR_EAGAIN)
//            THROW_FMT(FileRemoveError, "timeout removing '%s'", strZ(file));
//
//        if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL)
//        {
//            if (param.errorOnMissing || !storageSftpLibSsh2FxNoSuchFile(this, rc))
//            {
//                storageSftpEvalLibSsh2Error(
//                    rc, libssh2_sftp_last_error(this->sftpSession), &FileRemoveError,
//                    strNewFmt("unable to remove '%s'", strZ(file)), NULL);
//            }
//        }
//        else
//        {
//            if (param.errorOnMissing)
//            {
//                storageSftpEvalLibSsh2Error(
//                    rc, libssh2_sftp_last_error(this->sftpSession), &FileRemoveError,
//                    strNewFmt("unable to remove '%s'", strZ(file)), NULL);
//            }
//        }
//    }

    FUNCTION_LOG_RETURN_VOID();
}

/**********************************************************************************************************************************/
static StorageRead *
storageSftpNewRead(THIS_VOID, const String *const file, const bool ignoreMissing, const StorageInterfaceNewReadParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, file);
        FUNCTION_LOG_PARAM(BOOL, ignoreMissing);
        FUNCTION_LOG_PARAM(UINT64, param.offset);
        FUNCTION_LOG_PARAM(VARIANT, param.limit);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(file != NULL);

    FUNCTION_LOG_RETURN(
        STORAGE_READ,
        storageReadSftpNew(
            this, file, ignoreMissing, &this->session, &this->sftpSession, &this->sftpHandle, param.offset, param.limit));
}

/**********************************************************************************************************************************/
static StorageWrite *
storageSftpNewWrite(THIS_VOID, const String *const file, const StorageInterfaceNewWriteParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, file);
        FUNCTION_LOG_PARAM(MODE, param.modeFile);
        FUNCTION_LOG_PARAM(MODE, param.modePath);
        FUNCTION_LOG_PARAM(STRING, param.user);
        FUNCTION_LOG_PARAM(STRING, param.group);
        FUNCTION_LOG_PARAM(TIME, param.timeModified);
        FUNCTION_LOG_PARAM(BOOL, param.createPath);
        FUNCTION_LOG_PARAM(BOOL, param.syncFile);
        FUNCTION_LOG_PARAM(BOOL, param.syncPath);
        FUNCTION_LOG_PARAM(BOOL, param.atomic);
        FUNCTION_LOG_PARAM(BOOL, param.truncate);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(file != NULL);
    ASSERT(param.createPath);
    ASSERT(param.truncate);
    ASSERT(param.user == NULL);
    ASSERT(param.group == NULL);
    ASSERT(param.timeModified == 0);

    FUNCTION_LOG_RETURN(
        STORAGE_WRITE,
        storageWriteSftpNew(
            this, file, &this->session, &this->sftpSession, &this->sftpHandle, param.modeFile, param.modePath, param.user,
            param.group, param.timeModified, param.createPath, param.syncFile,
            this->interface.pathSync != NULL ? param.syncPath : false,
            param.atomic, param.truncate));
}

/**********************************************************************************************************************************/
static void
storageSftpPathCreate(
    THIS_VOID, const String *const path, const bool errorOnExists, const bool noParentCreate, const mode_t mode,
    const StorageInterfacePathCreateParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, path);
        FUNCTION_LOG_PARAM(BOOL, errorOnExists);
        FUNCTION_LOG_PARAM(BOOL, noParentCreate);
        FUNCTION_LOG_PARAM(MODE, mode);
        (void)param;                                                // No parameters are used
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(path != NULL);

    //int rc;

//    // Attempt to create the directory
//    do
//    {
//        rc = libssh2_sftp_mkdir_ex(this->sftpSession, strZ(path), (unsigned int)strSize(path), (int)mode);
//    }
//    while (storageSftpWaitFd(this, rc));
//
//    if (rc != 0)
//    {
//        if (rc == LIBSSH2_ERROR_EAGAIN)
//            THROW_FMT(PathCreateError, "timeout creating path '%s'", strZ(path));
//
//        if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL)
//        {
//            uint64_t sftpErrno = libssh2_sftp_last_error(this->sftpSession);
//
//            // libssh2 may return LIBSSH2_FX_FAILURE if the directory already exists
//            if (sftpErrno == LIBSSH2_FX_FAILURE)
//            {
//                // Check if the directory already exists
//                LIBSSH2_SFTP_ATTRIBUTES attr;
//
//                do
//                {
//                    rc = libssh2_sftp_stat_ex(
//                        this->sftpSession, strZ(path), (unsigned int)strSize(path), LIBSSH2_SFTP_STAT, &attr);
//                }
//                while (storageSftpWaitFd(this, rc));
//
//                if (rc == LIBSSH2_ERROR_EAGAIN)
//                    THROW_FMT(PathCreateError, "timeout stat'ing path '%s'", strZ(path));
//
//                // If rc = 0 then already exists
//                if (rc == 0 && errorOnExists)
//                {
//                    storageSftpEvalLibSsh2Error(
//                        rc, libssh2_sftp_last_error(this->sftpSession), &PathCreateError,
//                        strNewFmt("unable to create path '%s': path already exists", strZ(path)), NULL);
//                }
//            }
//            // If the parent path does not exist then create it if allowed
//            else if (sftpErrno == LIBSSH2_FX_NO_SUCH_FILE && !noParentCreate)
//            {
//                String *const pathParent = strPath(path);
//
//                storageInterfacePathCreateP(this, pathParent, errorOnExists, noParentCreate, mode);
//                storageInterfacePathCreateP(this, path, errorOnExists, noParentCreate, mode);
//
//                strFree(pathParent);
//            }
//            else if (sftpErrno != LIBSSH2_FX_FILE_ALREADY_EXISTS || errorOnExists)
//            {
//                storageSftpEvalLibSsh2Error(
//                    rc, sftpErrno, &PathCreateError, strNewFmt("sftp error unable to create path '%s'", strZ(path)), NULL);
//            }
//        }
//        else
//        {
//            storageSftpEvalLibSsh2Error(
//                rc, libssh2_sftp_last_error(this->sftpSession), &PathCreateError,
//                strNewFmt("ssh2 error [%d] unable to create path '%s'", rc, strZ(path)), NULL);
//        }
//    }

    FUNCTION_LOG_RETURN_VOID();
}

/**********************************************************************************************************************************/
static bool
storageSftpPathRemove(THIS_VOID, const String *const path, const bool recurse, const StorageInterfacePathRemoveParam param)
{
    THIS(StorageSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, this);
        FUNCTION_LOG_PARAM(STRING, path);
        FUNCTION_LOG_PARAM(BOOL, recurse);
        (void)param;                                                // No parameters are used
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(path != NULL);

    bool result = true;

//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        // Recurse if requested
//        if (recurse)
//        {
//            StorageList *const list = storageInterfaceListP(this, path, storageInfoLevelExists);
//
//            if (list != NULL)
//            {
//                MEM_CONTEXT_TEMP_RESET_BEGIN()
//                {
//                    for (unsigned int listIdx = 0; listIdx < storageLstSize(list); listIdx++)
//                    {
//                        const String *const file = strNewFmt("%s/%s", strZ(path), strZ(storageLstGet(list, listIdx).name));
//
//                        // Rather than stat the file to discover what type it is, just try to unlink it and see what happens
//                        int rc;
//
//                        do
//                        {
//                            rc = libssh2_sftp_unlink_ex(this->sftpSession, strZ(file), (unsigned int)strSize(file));
//                        }
//                        while (storageSftpWaitFd(this, rc));
//
//                        if (rc != 0)
//                        {
//                            if (rc == LIBSSH2_ERROR_EAGAIN)
//                                THROW_FMT(PathRemoveError, "timeout removing file '%s'", strZ(file));
//
//                            // Attempting to unlink a directory appears to return LIBSSH2_FX_FAILURE or LIBSSH2_FX_PERMISSION_DENIED
//                            if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL)
//                            {
//                                const uint64_t sftpErrno = libssh2_sftp_last_error(this->sftpSession);
//
//                                if (sftpErrno == LIBSSH2_FX_FAILURE || sftpErrno == LIBSSH2_FX_PERMISSION_DENIED)
//                                    storageInterfacePathRemoveP(this, file, true);
//                                else
//                                {
//                                    THROW_FMT(
//                                        PathRemoveError, STORAGE_ERROR_PATH_REMOVE_FILE " libssh sftp [%" PRIu64 "]", strZ(file),
//                                        sftpErrno);
//                                }
//                            }
//                            else
//                                THROW_FMT(PathRemoveError, STORAGE_ERROR_PATH_REMOVE_FILE " libssh ssh [%d]", strZ(file), rc);
//                        }
//
//                        // Reset the memory context occasionally so we don't use too much memory or slow down processing
//                        MEM_CONTEXT_TEMP_RESET(1000);
//                    }
//                }
//                MEM_CONTEXT_TEMP_END();
//            }
//        }
//
//        // Delete the path
//        int rc;
//
//        do
//        {
//            rc = libssh2_sftp_rmdir_ex(this->sftpSession, strZ(path), (unsigned int)strSize(path));
//        }
//        while (storageSftpWaitFd(this, rc));
//
//        if (rc != 0)
//        {
//            if (rc == LIBSSH2_ERROR_EAGAIN)
//                THROW_FMT(PathRemoveError, "timeout removing path '%s'", strZ(path));
//
//            if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL)
//            {
//                const uint64_t sftpErrno = libssh2_sftp_last_error(this->sftpSession);
//
//                if (sftpErrno != LIBSSH2_FX_NO_SUCH_FILE)
//                    THROW_FMT(PathRemoveError, STORAGE_ERROR_PATH_REMOVE " sftp error [%" PRIu64 "]", strZ(path), sftpErrno);
//
//                // Path does not exist
//                result = false;
//            }
//            else
//            {
//                // Path does not exist
//                result = false;
//
//                storageSftpEvalLibSsh2Error(
//                    rc, libssh2_sftp_last_error(this->sftpSession), &PathRemoveError,
//                    strNewFmt(STORAGE_ERROR_PATH_REMOVE, strZ(path)), NULL);
//            }
//        }
//    }
//    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(BOOL, result);
}

/**********************************************************************************************************************************/
static const StorageInterface storageInterfaceSftp =
{
    .feature = 1 << storageFeaturePath | 1 << storageFeatureInfoDetail,

    .info = storageSftpInfo,
    .list = storageSftpList,
    .newRead = storageSftpNewRead,
    .newWrite = storageSftpNewWrite,
    .pathCreate = storageSftpPathCreate,
    .pathRemove = storageSftpPathRemove,
    .remove = storageSftpRemove,
};

FN_EXTERN Storage *
storageSftpNew(
    const String *const path, const String *const host, const unsigned int port, const String *const user,
    const TimeMSec timeout, const String *const keyPriv, const StringId hostKeyHashType, const StorageSftpNewParam param)
{
    FUNCTION_LOG_BEGIN(logLevelDebug);
        FUNCTION_LOG_PARAM(STRING, path);
        FUNCTION_LOG_PARAM(STRING, host);
        FUNCTION_LOG_PARAM(UINT, port);
        FUNCTION_LOG_PARAM(STRING, user);
        FUNCTION_LOG_PARAM(TIME_MSEC, timeout);
        FUNCTION_LOG_PARAM(STRING, keyPriv);
        FUNCTION_LOG_PARAM(STRING_ID, hostKeyHashType);
        FUNCTION_LOG_PARAM(STRING, param.keyPub);
        FUNCTION_TEST_PARAM(STRING, param.keyPassphrase);
        FUNCTION_LOG_PARAM(STRING_ID, param.hostKeyCheckType);
        FUNCTION_LOG_PARAM(STRING, param.hostFingerprint);
        FUNCTION_LOG_PARAM(STRING_LIST, param.knownHosts);
        FUNCTION_LOG_PARAM(MODE, param.modeFile);
        FUNCTION_LOG_PARAM(MODE, param.modePath);
        FUNCTION_LOG_PARAM(BOOL, param.write);
        FUNCTION_LOG_PARAM(FUNCTIONP, param.pathExpressionFunction);
    FUNCTION_LOG_END();

    ASSERT(path != NULL);
    ASSERT(host != NULL);
    ASSERT(port != 0);
    ASSERT(user != NULL);
    ASSERT(keyPriv != NULL);
    ASSERT(hostKeyHashType != 0);
    // Initialize user module
    userInit();

    // Create the object
    OBJ_NEW_BEGIN(StorageSftp, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (StorageSftp)
        {
            .interface = storageInterfaceSftp,
            .timeout = timeout,
        };

        // Init SSH session
        ssh_init();

        this->session = ssh_new();
        if (this->session == NULL)
            THROW_FMT(ServiceError, "unable to init libssh session");

        // Set the sftp socket fd
        this->ioSession = ioClientOpen(sckClientNew(host, port, timeout, timeout));
        int socketFd = ioSessionFd(this->ioSession);

        if (ssh_options_set(this->session, SSH_OPTIONS_FD, &socketFd) < SSH_OK)
        {
            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to set sftp socket fd [%d]", socketFd);
        }

        // Set the sftp user
        if (ssh_options_set(this->session, SSH_OPTIONS_USER, strZ(user)) < SSH_OK)
        {
            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to set sftp user [%s]", strZ(user));
        }

        // Set the sftp host
        if (ssh_options_set(this->session, SSH_OPTIONS_HOST, strZ(host)) < SSH_OK)
        {
            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to set sftp host [%s]", strZ(host));
        }

        // Set the sftp host port
        if (ssh_options_set(this->session, SSH_OPTIONS_PORT, &port) < SSH_OK)
        {
            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to set sftp port [%u]", port);
        }

        // Make the connection
        int rc;
        do
        {
            rc = ssh_connect(this->session);
        }
        while (storageSftpWaitFd(this, rc));

        if (rc < SSH_OK)
        {
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to connect to sftp host [%s]", strZ(host));
        }

        int hashType = SSH_PUBLICKEY_HASH_SHA1;
        size_t hashSize = 0;

        // Verify that the fingerprint[N] buffer declared below is large enough when adding a new hashType
        switch (hostKeyHashType)
        {
            case hashTypeMd5:
                hashType = SSH_PUBLICKEY_HASH_MD5;
                break;

            case hashTypeSha1:
                hashType = SSH_PUBLICKEY_HASH_SHA1;
                break;

            case hashTypeSha256:
                hashType = SSH_PUBLICKEY_HASH_SHA256;
                break;

            default:
                THROW_FMT(ServiceError, "requested ssh hostkey hash type (%s) not available", strZ(strIdToStr(hostKeyHashType)));
                break;
        }

        // Compare fingerprint if provided else check known hosts files for a match
        if (param.hostKeyCheckType == SFTP_STRICT_HOSTKEY_CHECKING_FINGERPRINT)
        {
            ssh_key srv_pubkey;

            if (ssh_get_server_publickey(this->session, &srv_pubkey) < SSH_OK)
            {
                ssh_disconnect(this->session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(this->session);
                THROW_FMT(ServiceError, "unable to get server public key");
            }

            unsigned char *hash;
            if (ssh_get_publickey_hash(srv_pubkey, hashType, &hash, &hashSize) < SSH_OK)
            {
                SSH_KEY_FREE(srv_pubkey);
                ssh_disconnect(this->session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(this->session);
                THROW_FMT(ServiceError, "unable to get public key hash");
            }

            char *fingerprint = ssh_get_fingerprint_hash(hashType, hash, hashSize);
            if (fingerprint == NULL)
            {
                ssh_clean_pubkey_hash(&hash);
                SSH_KEY_FREE(srv_pubkey);
                ssh_disconnect(this->session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(this->session);
                THROW_FMT(ServiceError, "unable to get fingerprint hash");
            }

            MEM_CONTEXT_TEMP_BEGIN()
            {
                // Check if the user provided fingerprint is prepended with the hash type
                if (!strBeginsWithZ(strLower(strDup(param.hostFingerprint)), "sha256:") &&
                    !strBeginsWithZ(strLower(strDup(param.hostFingerprint)), "md5:"))
                {
                    // If not, then skip the prepended hash type on the server fingerprint
                    memmove(fingerprint, strchr(fingerprint, ':') + 1, strlen(fingerprint));
                }
            }
            MEM_CONTEXT_TEMP_END();

            ssh_clean_pubkey_hash(&hash);
            SSH_KEY_FREE(srv_pubkey);

            if (strcmp(fingerprint, strZ(param.hostFingerprint)) != 0)
            {
                ssh_disconnect(this->session);

                // Free the ssh session - this is safe to do even if session is NULL. This function returns void
                ssh_free(this->session);

                THROW_FMT(
                    ServiceError, "host [%s] and configured fingerprint (repo-sftp-host-fingerprint) [%s] do not match",
                    fingerprint, strZ(param.hostFingerprint));
            }

            SSH_STRING_FREE_CHAR(fingerprint);
        }
        else if (param.hostKeyCheckType != SFTP_STRICT_HOSTKEY_CHECKING_NONE)
        {
            // Check the known hosts file(s) for a match
            verify_knownhost(this->session, param.knownHosts, param.hostKeyCheckType, host);

//            // Init the known host collection
//            LIBSSH2_KNOWNHOSTS *const knownHostsList = libssh2_knownhost_init(this->session);
//
//            if (knownHostsList == NULL)
//            {
//                const int rc = libssh2_session_last_errno(this->session);
//
//                THROW_FMT(
//                    ServiceError,
//                    "failure during libssh2_knownhost_init: libssh2 errno [%d] %s", rc,
//                    strZ(storageSftpLibSsh2SessionLastError(this->session)));
//            }
//
//            // Get the list of known host files to search
//            const StringList *const knownHostsPathList = storageSftpKnownHostsFilesList(param.knownHosts);
//
//            // Loop through the list of known host files
//            for (unsigned int listIdx = 0; listIdx < strLstSize(knownHostsPathList); listIdx++)
//            {
//                const char *const currentKnownHostFile = strZNull(strLstGet(knownHostsPathList, listIdx));
//
//                // Read the known hosts file entries into the collection, log message for readfile status.
//                // libssh2_knownhost_readfile() returns the number of successfully loaded hosts or a negative value on error, an
//                // empty known hosts file will return 0.
//                if ((rc = libssh2_knownhost_readfile(knownHostsList, currentKnownHostFile, LIBSSH2_KNOWNHOST_FILE_OPENSSH)) <= 0)
//                {
//                    if (rc == 0)
//                        LOG_DETAIL_FMT("libssh2 '%s' file is empty", currentKnownHostFile);
//                    else
//                    {
//                        LOG_DETAIL_FMT(
//                            "libssh2 read '%s' failed: libssh2 errno [%d] %s", currentKnownHostFile, rc,
//                            strZ(storageSftpLibSsh2SessionLastError(this->session)));
//                    }
//                }
//                else
//                    LOG_DETAIL_FMT("libssh2 read '%s' succeeded", currentKnownHostFile);
//            }
//
//            // Get the remote host key
//            size_t hostKeyLen;
//            int hostKeyType;
//            const char *const hostKey = libssh2_session_hostkey(this->session, &hostKeyLen, &hostKeyType);
//
//            // Check for a match in known hosts files else throw an error if no host key was retrieved
//            if (hostKey != NULL)
//            {
//                rc = libssh2_knownhost_checkp(
//                    knownHostsList, strZ(host), (int)port, hostKey, hostKeyLen,
//                    LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, NULL);
//
//                // Handle check success/failure
//                if (rc == LIBSSH2_KNOWNHOST_CHECK_MATCH)
//                    LOG_DETAIL_FMT("known hosts match found for '%s'", strZ(host));
//                else
//                {
//                    // Handle failure to match in a similar manner as ssh_config StrictHostKeyChecking. If this flag is set to
//                    // "strict", never automatically add host keys to the ~/.ssh/known_hosts file, and refuse to connect to hosts
//                    // whose host key has changed. This option forces the user to manually add all new hosts. If this flag is set to
//                    // "accept-new" then automatically add new host keys to the user known hosts files, but do not permit
//                    // connections to hosts with changed host keys.
//                    switch (param.hostKeyCheckType)
//                    {
//                        case SFTP_STRICT_HOSTKEY_CHECKING_STRICT:
//                        {
//                            // Throw an error when set to strict and we have any result other than match
//                            libssh2_knownhost_free(knownHostsList);
//
//                            THROW_FMT(
//                                ServiceError, "known hosts failure: '%s' %s [%d]: check type [%s]", strZ(host),
//                                storageSftpKnownHostCheckpFailureMsg(rc), rc, strZ(strIdToStr(param.hostKeyCheckType)));
//
//                            break;
//                        }
//
//                        default:
//                        {
//                            ASSERT(param.hostKeyCheckType == SFTP_STRICT_HOSTKEY_CHECKING_ACCEPT_NEW);
//
//                            // Throw an error when set to accept-new and match fails or mismatches else add the new host key to the
//                            // user's known_hosts file
//                            if (rc == LIBSSH2_KNOWNHOST_CHECK_MISMATCH || rc == LIBSSH2_KNOWNHOST_CHECK_FAILURE)
//                            {
//                                // Free the known hosts list
//                                libssh2_knownhost_free(knownHostsList);
//
//                                THROW_FMT(
//                                    ServiceError, "known hosts failure: '%s': %s [%d]: check type [%s]", strZ(host),
//                                    storageSftpKnownHostCheckpFailureMsg(rc), rc,
//                                    strZ(strIdToStr(param.hostKeyCheckType)));
//                            }
//                            else
//                                storageSftpUpdateKnownHostsFile(this, hostKeyType, host, hostKey, hostKeyLen);
//
//                            break;
//                        }
//                    }
//                }
//            }
//            else
//            {
//                THROW_FMT(
//                    ServiceError,
//                    "libssh2_session_hostkey failed to get hostkey: libssh2 error [%d]", libssh2_session_last_errno(this->session));
//            }
//
//            // Free the known hosts list
//            libssh2_knownhost_free(knownHostsList);
        }

        // Perform public key authorization
        // Use provided public key or default to appending .pub to provided private key, expand leading tilde key file paths if
        // needed
        String *const privKeyPath = regExpMatchOne(STRDEF("^ *~"), keyPriv) ? storageSftpExpandTildePath(keyPriv) : strDup(keyPriv);

        String *pubKeyPath =
            param.keyPub != NULL && regExpMatchOne(STRDEF("^ *~"), param.keyPub) ?
            storageSftpExpandTildePath(param.keyPub) :
            (param.keyPub != NULL ? strDup(param.keyPub) : strNewFmt("%s.pub", strZ(privKeyPath)));

        // Import the public key
        ssh_key pubKey = NULL;
        if ((rc = ssh_pki_import_pubkey_file(strZ(pubKeyPath), &pubKey)) != SSH_OK)
        {
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to import public key file '%s' [%d]", strZ(pubKeyPath), rc);
        }

        // Offer the public key to the ssh server
        do
        {
            rc = ssh_userauth_try_publickey(this->session, strZ(user), pubKey);
        }
        while (storageSftpWaitFd(this, rc));

        if (rc != SSH_AUTH_SUCCESS)
        {
            SSH_KEY_FREE(pubKey);
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to authenticate with public key: %s for %s [%d]", strZ(pubKeyPath), strZ(user), rc);
        }

        // Retrieve the private key
        ssh_key privKey = NULL;

        if ((rc = ssh_pki_import_privkey_file(strZ(privKeyPath), NULL, NULL, NULL, &privKey)) != SSH_OK)
        {
            SSH_KEY_FREE(pubKey);
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "unable to import private key file '%s' [%d]", strZ(privKeyPath), rc);
        }

        // Authenticate with the private key
        do
        {
            rc = ssh_userauth_publickey(this->session, strZ(user), privKey);
        }
        while (storageSftpWaitFd(this, rc));

        if (rc != SSH_AUTH_SUCCESS)
        {
            SSH_KEY_FREE(privKey);
            SSH_KEY_FREE(pubKey);
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(
                ServiceError, "unable to authenticate with private key: %s for user %s [%d]", strZ(privKeyPath), strZ(user), rc);
        }

        SSH_KEY_FREE(privKey);
        SSH_KEY_FREE(pubKey);
        strFree(pubKeyPath);
        strFree(privKeyPath);

        // Allocate SFTP session
        this->sftpSession = sftp_new(this->session);
        if (this->sftpSession == NULL)
        {
            const String *const errMsg = strNewFmt(
                "unable to allocate sftp session: %s",
                strZ(strNewFmt("%s [%d]", ssh_get_error(this->session), ssh_get_error_code(this->session))));

            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "%s", strZ(errMsg));
        }

        // Init FTP session
        if (sftp_init(this->sftpSession) != SSH_OK)
        {
            const String *const errMsg =
                strNewFmt(
                    "unable to init sftp session: %s",
                    strZ(strNewFmt("%s [%d] sftp error [%d]", ssh_get_error(this->session), ssh_get_error_code(this->session),
                        sftp_get_error(this->sftpSession))));

            // Free the sftp session - this is safe to do even if sftpSession is NULL. This function returns void
            sftp_free(this->sftpSession);
            ssh_disconnect(this->session);

            // Free the ssh session - this is safe to do even if session is NULL. This function returns void
            ssh_free(this->session);
            THROW_FMT(ServiceError, "%s", strZ(errMsg));
        }


//
//        // Perform public key authorization, expand leading tilde key file paths if needed
//        String *const privKeyPath = regExpMatchOne(STRDEF("^ *~"), keyPriv) ? storageSftpExpandTildePath(keyPriv) : strDup(keyPriv);
//        String *const pubKeyPath =
//            param.keyPub != NULL && regExpMatchOne(STRDEF("^ *~"), param.keyPub) ?
//                storageSftpExpandTildePath(param.keyPub) : strDup(param.keyPub);
//
//        do
//        {
//            rc = libssh2_userauth_publickey_fromfile(
//                this->session, strZ(user), strZNull(pubKeyPath), strZ(privKeyPath), strZNull(param.keyPassphrase));
//        }
//        while (storageSftpWaitFd(this, rc));
//
//        strFree(privKeyPath);
//        strFree(pubKeyPath);
//
//        if (rc != 0)
//        {
//            if (rc == LIBSSH2_ERROR_EAGAIN)
//                THROW_FMT(ServiceError, "timeout during public key authentication");
//
//            storageSftpEvalLibSsh2Error(
//                rc, libssh2_sftp_last_error(this->sftpSession), &ServiceError,
//                STRDEF("public key authentication failed"),
//                STRDEF(
//                    "HINT: libssh2 compiled against non-openssl libraries requires --repo-sftp-private-key-file and"
//                    " --repo-sftp-public-key-file to be provided\n"
//                    "HINT: libssh2 versions before 1.9.0 expect a PEM format keypair, try ssh-keygen -m PEM -t rsa -P \"\" to"
//                    " generate the keypair"));
//        }
//
//        // Init the sftp session
//        do
//        {
//            this->sftpSession = libssh2_sftp_init(this->session);
//        }
//        while (this->sftpSession == NULL && storageSftpWaitFd(this, libssh2_session_last_errno(this->session)));
//
//        if (this->sftpSession == NULL)
//        {
//            if (libssh2_session_last_errno(this->session) == LIBSSH2_ERROR_EAGAIN)
//                THROW_FMT(ServiceError, "timeout during init of libssh2_sftp session");
//            else
//            {
//                storageSftpEvalLibSsh2Error(
//                    rc, libssh2_sftp_last_error(this->sftpSession), &ServiceError,
//                    strNewFmt("unable to init libssh2_sftp session"), NULL);
//            }
//        }
//
//        // Ensure libssh/libssh sftp resources freed
        memContextCallbackSet(objMemContext(this), storageSftpLibSshSessionFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        STORAGE,
        storageNew(
            STORAGE_SFTP_TYPE, path, param.modeFile == 0 ? STORAGE_MODE_FILE_DEFAULT : param.modeFile,
            param.modePath == 0 ? STORAGE_MODE_PATH_DEFAULT : param.modePath, param.write, param.pathExpressionFunction,
            this, this->interface));
}

#else
int
satisfyCodeCoverageWhenLibsshIsNotLinkedStorage(void)
{
    return 0;
}

#endif // HAVE_LIBSSH
