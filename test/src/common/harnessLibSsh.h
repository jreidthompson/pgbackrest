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
//#define HRNLIBSSH_SESSION_BLOCK_DIRECTIONS                          "ssh_session_block_directions"
//#define HRNLIBSSH_SESSION_HANDSHAKE                                 "ssh_session_handshake"
//#define HRNLIBSSH_SESSION_HOSTKEY                                   "ssh_session_hostkey"
//#define HRNLIBSSH_SESSION_INIT_EX                                   "ssh_session_init_ex"
//#define HRNLIBSSH_SESSION_LAST_ERRNO                                "ssh_session_last_errno"
//#define HRNLIBSSH_SESSION_LAST_ERROR                                "ssh_session_last_error"
//#define HRNLIBSSH_SFTP_CLOSE_HANDLE                                 "ssh_sftp_close_handle"
//#define HRNLIBSSH_SFTP_FSYNC                                        "ssh_sftp_fsync"
//#define HRNLIBSSH_SFTP_INIT                                         "ssh_sftp_init"
//#define HRNLIBSSH_SFTP_LAST_ERROR                                   "ssh_sftp_last_error"
//#define HRNLIBSSH_SFTP_MKDIR_EX                                     "ssh_sftp_mkdir_ex"
//#define HRNLIBSSH_SFTP_OPEN_EX                                      "ssh_sftp_open_ex"
//#define HRNLIBSSH_SFTP_READ                                         "ssh_sftp_read"
//#define HRNLIBSSH_SFTP_READDIR_EX                                   "ssh_sftp_readdir_ex"
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
**********************************************************************************************************************************
// Set of functions mimicking libssh inititialization and authorization
#define HRNLIBSSH_MACRO_STARTUP()                                                                                                 \
    {.function = HRNLIBSSH_INIT, .param = "[0]", .resultInt = 0},                                                                 \
    {.function = HRNLIBSSH_SESSION_INIT_EX, .param = "[null,null,null,null]"},                                                    \
    {.function = HRNLIBSSH_SESSION_HANDSHAKE, .param = HANDSHAKE_PARAM, .resultInt = 0},                                          \
    {.function = HRNLIBSSH_KNOWNHOST_INIT},                                                                                       \
    {.function = HRNLIBSSH_KNOWNHOST_READFILE, .param = "[\"" KNOWNHOSTS_FILE_CSTR "\",1]", .resultInt = 5},                      \
    {.function = HRNLIBSSH_SESSION_HOSTKEY, .len = 20, .type = LIBSSH_HOSTKEY_TYPE_RSA, .resultZ = HOSTKEY},                     \
    {.function = HRNLIBSSH_KNOWNHOST_CHECKP, .param = "[\"localhost\",22,\"" HOSTKEY "\",20,65537]",                              \
     .resultInt = LIBSSH_KNOWNHOST_CHECK_MATCH},                                                                                  \
    {.function = HRNLIBSSH_USERAUTH_PUBLICKEY_FROMFILE_EX,                                                                        \
    .param = "[\"" TEST_USER "\"," TEST_USER_LEN ",\"" KEYPUB_CSTR "\",\"" KEYPRIV_CSTR "\",null]",                                \
    .resultInt = 0},                                                                                                               \
    {.function = HRNLIBSSH_SFTP_INIT}

// Set of functions mimicking libssh shutdown and disconnect
#define HRNLIBSSH_MACRO_SHUTDOWN()                                                                                                \
    {.function = HRNLIBSSH_SFTP_SHUTDOWN, .resultInt = 0},                                                                        \
    {.function = HRNLIBSSH_SESSION_DISCONNECT_EX, .param ="[11,\"pgBackRest instance shutdown\",\"\"]", .resultInt = 0},          \
    {.function = HRNLIBSSH_SESSION_FREE, .resultInt = 0},                                                                         \
    {.function = NULL}                                                                                                             \

// Older systems do not support LIBSSH_HOSTKEY_HASH_SHA256
#ifdef LIBSSH_HOSTKEY_HASH_SHA256
#define HOSTKEY_HASH_ENTRY()                                                                                                       \
    {.function = HRNLIBSSH_HOSTKEY_HASH, .param = "[3]", .resultZ = "12345678910123456789"}
#else
#define HOSTKEY_HASH_ENTRY()                                                                                                       \
    {.function = HRNLIBSSH_HOSTKEY_HASH, .param = "[2]", .resultZ = "12345678910123456789"}
#endif
*/
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
//    uint64_t attrPerms;                                             // libssh attr perms
//    uint64_t atime, mtime;                                          // libssh timestamps
//    uint64_t uid, gid;                                              // libssh uid/gid
//    uint64_t filesize;                                              // libssh filesize
//    uint64_t offset;                                                // libssh seek offset
//    const String *symlinkExTarget;                                  // libssh_sftp_symlink_ex target
//    const String *fileName;                                         // libssh_readdir* libssh_stat* filename
//    const String *readBuffer;                                       // what to copy into read buffer
    TimeMSec sleep;                                                 // Sleep specified milliseconds before returning from function
    size_t len;                                                     // libssh_session_hostkey len
    int type;                                                       // libssh_session_hostkey type
    char *errMsg;                                                   // libssh_session_last_error error msg
    enum ssh_known_hosts_e state;                                        // libssh known host check state
} HrnLibSsh;

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
void hrnLibSshScriptSet(HrnLibSsh *hrnLibSshScriptParam);

#endif // HARNESS_LIBSSH_REAL

#endif // HAVE_LIBSSH

#endif // TEST_COMMON_HARNESS_LIBSSH_H
