/***********************************************************************************************************************************
libssh Test Harness

Scripted testing for libssh so exact results can be returned for unit testing. See sftp unit tests for usage examples.
***********************************************************************************************************************************/
#ifndef TEST_COMMON_HARNESS_LIBSSH_H
#define TEST_COMMON_HARNESS_LIBSSH_H

#ifdef HAVE_LIBSSH

#ifndef HARNESS_LIBSSH_REAL

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdbool.h>

#include "common/macro.h"
#include "common/time.h"
#include "version.h"

/***********************************************************************************************************************************
libssh authorization constants
***********************************************************************************************************************************/
#define KEYPRIV                                                     STRDEF("/home/" TEST_USER "/.ssh/id_rsa")
#define KEYPUB                                                      STRDEF("/home/" TEST_USER "/.ssh/id_rsa.pub")
#define KEYPRIV_CSTR                                                "/home/" TEST_USER "/.ssh/id_rsa"
#define KEYPUB_CSTR                                                 "/home/" TEST_USER "/.ssh/id_rsa.pub"
#define TILDE_KEYPRIV                                               STRDEF("~/.ssh/id_rsa")
#define TILDE_KEYPUB                                                STRDEF("~/.ssh/id_rsa.pub")
#define TILDE_KEYPRIV_CSTR                                          "~/.ssh/id_rsa"
#define TILDE_KEYPUB_CSTR                                           "~/.ssh/id_rsa.pub"
#define KNOWNHOSTS_FILE_CSTR                                        "/home/" TEST_USER "/.ssh/known_hosts"
#define KNOWNHOSTS_FILE_CSTR                                        "/home/" TEST_USER "/.ssh/known_hosts"
#define KNOWNHOSTS2_FILE_CSTR                                       "/home/" TEST_USER "/.ssh/known_hosts2"
#define ETC_KNOWNHOSTS_FILE_CSTR                                    "/etc/ssh/ssh_known_hosts"
#define ETC_KNOWNHOSTS2_FILE_CSTR                                   "/etc/ssh/ssh_known_hosts2"
#define HOSTKEY                                                     "12345678901234567890"

/***********************************************************************************************************************************
Function constants
***********************************************************************************************************************************/
#define HRNLIBSSH_INIT                                              "ssh_init"
#define HRNLIBSSH_NEW                                               "ssh_new"
#define HRNLIBSSH_FREE                                              "ssh_free"
#define HRNLIBSSH_OPTIONS_SET                                       "ssh_options_set"
#define HRNLIBSSH_OPTIONS_GET                                       "ssh_options_get"
#define HRNLIBSSH_CONNECT                                           "ssh_connect"
#define HRNLIBSSH_DISCONNECT                                        "ssh_disconnect"
#define HRNLIBSSH_GET_SERVER_PUBLICKEY                              "ssh_get_server_publickey"
#define HRNLIBSSH_GET_PUBLICKEY_HASH                                "ssh_get_publickey_hash"
#define HRNLIBSSH_GET_FINGERPRINT_HASH                              "ssh_get_fingerprint_hash"
#define HRNLIBSSH_KEY_FREE                                          "ssh_key_free"
#define HRNLIBSSH_CLEAN_PUBKEY_HASH                                 "ssh_clean_pubkey_hash"
#define HRNLIBSSH_SESSION_IS_KNOWN_SERVER                           "ssh_session_is_known_server"
#define HRNLIBSSH_GET_ERROR                                         "ssh_get_error"
#define HRNLIBSSH_GET_ERROR_CODE                                    "ssh_get_error_code"
#define HRNLIBSSH_SESSION_UPDATE_KNOWN_HOSTS                        "ssh_session_update_known_hosts"
#define HRNLIBSSH_SFTP_NEW                                          "sftp_new"
#define HRNLIBSSH_SFTP_INIT                                         "sftp_init"
#define HRNLIBSSH_SFTP_FREE                                         "sftp_free"
#define HRNLIBSSH_SFTP_GET_ERROR                                    "sftp_get_error"
#define HRNLIBSSH_SESSION_UPDATE_KNOWN_HOSTS                        "ssh_session_update_known_hosts"
#define HRNLIBSSH_GET_POLL_FLAGS                                    "ssh_get_poll_flags"
#define HRNLIBSSH_USERAUTH_TRY_PUBLICKEY                            "ssh_userauth_try_publickey"
#define HRNLIBSSH_USERAUTH_PUBLICKEY                                "ssh_userauth_publickey"
#define HRNLIBSSH_PKI_IMPORT_PUBKEY_FILE                            "ssh_pki_import_pubkey_file"
#define HRNLIBSSH_PKI_IMPORT_PRIVKEY_FILE                           "ssh_pki_import_privkey_file"
#define HRNLIBSSH_SFTP_STAT                                         "sftp_stat"
#define HRNLIBSSH_SFTP_LSTAT                                        "sftp_lstat"
#define HRNLIBSSH_FINALIZE                                          "ssh_finalize"
#define HRNLIBSSH_SFTP_READLINK                                     "sftp_readlink"
#define HRNLIBSSH_SFTP_OPENDIR                                      "sftp_opendir"
#define HRNLIBSSH_SFTP_READDIR                                      "sftp_readdir"
#define HRNLIBSSH_SFTP_CLOSEDIR                                     "sftp_closedir"
#define HRNLIBSSH_SFTP_DIR_EOF                                      "sftp_dir_eof"
//#define HRNLIBSSH_SESSION_INIT_EX                                   "ssh_session_init_ex"
//#define HRNLIBSSH_SESSION_LAST_ERRNO                                "ssh_session_last_errno"
//#define HRNLIBSSH_SESSION_LAST_ERROR                                "ssh_session_last_error"
//#define HRNLIBSSH_SFTP_FSYNC                                        "ssh_sftp_fsync"
//#define HRNLIBSSH_SFTP_INIT                                         "ssh_sftp_init"
//#define HRNLIBSSH_SFTP_LAST_ERROR                                   "ssh_sftp_last_error"
//#define HRNLIBSSH_SFTP_MKDIR_EX                                     "ssh_sftp_mkdir_ex"
//#define HRNLIBSSH_SFTP_READ                                         "ssh_sftp_read"
//#define HRNLIBSSH_SFTP_RENAME_EX                                    "ssh_sftp_rename_ex"
//#define HRNLIBSSH_SFTP_RMDIR_EX                                     "ssh_sftp_rmdir_ex"
//#define HRNLIBSSH_SFTP_SEEK64                                       "ssh_sftp_seek64"
//#define HRNLIBSSH_SFTP_SHUTDOWN                                     "ssh_sftp_shutdown"
//#define HRNLIBSSH_SFTP_STAT_EX                                      "ssh_sftp_stat_ex"
//#define HRNLIBSSH_SFTP_SYMLINK_EX                                   "ssh_sftp_symlink_ex"
//#define HRNLIBSSH_SFTP_UNLINK_EX                                    "ssh_sftp_unlink_ex"
//#define HRNLIBSSH_SFTP_WRITE                                        "ssh_sftp_write"
//#define HRNLIBSSH_USERAUTH_PUBLICKEY_FROMFILE_EX                    "ssh_userauth_publickey_fromfile_ex"

/***********************************************************************************************************************************
//Macros for defining groups of functions that implement commands
***********************************************************************************************************************************/
// Set of functions mimicking libssh inititialization and authorization
#define HRNLIBSSH_MACRO_STARTUP()                                                                                                  \
    {.function = HRNLIBSSH_NEW, .resultNull = false},                                                                              \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[3,1163581]", .resultInt = SSH_OK},                                              \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[4,\"" TEST_USER "\"]", .resultInt = SSH_OK},                                    \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[0,\"localhost\"]", .resultInt = SSH_OK},                                        \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[1,22]", .resultInt = SSH_OK},                                                   \
    {.function = HRNLIBSSH_CONNECT, .resultInt = SSH_OK},                                                                          \
    {.function = HRNLIBSSH_GET_SERVER_PUBLICKEY, .resultInt = SSH_OK, .resultZ = "server public key"},                             \
    {.function = HRNLIBSSH_GET_PUBLICKEY_HASH, .resultInt = SSH_OK},                                                               \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[8,\"/home/" TEST_USER "/.ssh/known_hosts\"]", .resultInt = SSH_OK},             \
    {.function = HRNLIBSSH_SESSION_IS_KNOWN_SERVER, .resultInt = SSH_KNOWN_HOSTS_OK},                                              \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[8,null]", .resultInt = SSH_OK},                                                 \
    {.function = HRNLIBSSH_OPTIONS_SET, .param = "[35,null]", .resultInt = SSH_OK},                                                \
    {.function = HRNLIBSSH_PKI_IMPORT_PUBKEY_FILE, .resultInt = SSH_OK},                                                           \
    {.function = HRNLIBSSH_USERAUTH_TRY_PUBLICKEY, .resultInt = SSH_AUTH_SUCCESS, .param = "[\"" TEST_USER "\"]"},                 \
    {.function = HRNLIBSSH_PKI_IMPORT_PRIVKEY_FILE, .resultInt = SSH_OK},                                                          \
    {.function = HRNLIBSSH_USERAUTH_PUBLICKEY, .resultInt = SSH_AUTH_SUCCESS, .param = "[\"" TEST_USER "\"]"},                     \
    {.function = HRNLIBSSH_SFTP_NEW, .resultNull = false},                                                                         \
    {.function = HRNLIBSSH_SFTP_INIT, .resultInt = SSH_OK}


// Set of functions mimicking libssh shutdown and disconnect
#define HRNLIBSSH_MACRO_SHUTDOWN()                                                                                                 \
    {.function = HRNLIBSSH_SFTP_FREE},                                                                                             \
    {.function = HRNLIBSSH_DISCONNECT},                                                                                            \
    {.function = HRNLIBSSH_FREE},                                                                                                  \
    {.function = HRNLIBSSH_FINALIZE, .resultInt = 0},                                                                              \
    {.function = NULL}                                                                                                             \

/***********************************************************************************************************************************
Structure for scripting libssh responses
***********************************************************************************************************************************/
typedef struct HrnLibSsh
{
    unsigned int session;                                           // Session number when multiple sessions are run concurrently
    const char *function;                                           // Function call expected
    const char *param;                                              // Params expected by the function for verification
    int resultInt;                                                  // Int result value
    uint64_t resultUInt;                                            // UInt result value
    const char *resultZ;                                            // Zero-terminated result value
    bool resultNull;                                                // Return null from function that normally returns a struct ptr
    uint64_t flags;                                                 // libssh flags
    uint32_t attrPerms;                                             // libssh attr perms
    uint64_t mtime64;                                               // libssh timestamp
    uint32_t uid, gid;                                              // libssh uid/gid
    uint64_t filesize;                                              // libssh filesize
    uint64_t offset;                                                // libssh seek offset
    const String *symlinkExTarget;                                  // libssh sftp symlink target
    const String *fileName;                                         // libssh_readdir* libssh stat* filename
//    const String *readBuffer;                                       // what to copy into read buffer
    TimeMSec sleep;                                                 // Sleep specified milliseconds before returning from function
    size_t len;                                                     // libssh session hostkey len
    int type;                                                       // libssh session hostkey type
    char *errMsg;                                                   // libssh session last error error msg
    enum ssh_known_hosts_e state;                                   // libssh known host check state
    sftp_attributes attrs;                                          // libssh attrs
} HrnLibSsh;

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
void hrnLibSshScriptSet(HrnLibSsh *hrnLibSshScriptParam);

#endif // HARNESS_LIBSSH_REAL

#endif // HAVE_LIBSSH

#endif // TEST_COMMON_HARNESS_LIBSSH_H
