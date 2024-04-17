/***********************************************************************************************************************************
libssh Test Harness

Scripted testing for libssh so exact results can be returned for unit testing. See sftp unit tests for usage examples.
***********************************************************************************************************************************/
#ifndef TEST_COMMON_HARNESS_LIBSSH_H
#define TEST_COMMON_HARNESS_LIBSSH_H

#ifdef HAVE_LIBSSH

#ifndef HARNESS_LIBSSH_REAL

#include <libssh.h>
#include <libssh_sftp.h>
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
//#define HRNLIBSSH_HOSTKEY_HASH                                      "libssh_hostkey_hash"
#define HRNLIBSSH_INIT                                                "libssh_init"
//#define HRNLIBSSH_KNOWNHOST_ADDC                                    "libssh_knownhost_addc"
//#define HRNLIBSSH_KNOWNHOST_CHECKP                                  "libssh_knownhost_checkp"
//#define HRNLIBSSH_KNOWNHOST_FREE                                    "libssh_knownhost_free"
//#define HRNLIBSSH_KNOWNHOST_INIT                                    "libssh_knownhost_init"
//#define HRNLIBSSH_KNOWNHOST_READFILE                                "libssh_knownhost_readfile"
//#define HRNLIBSSH_KNOWNHOST_WRITEFILE                               "libssh_knownhost_writefile"
//#define HRNLIBSSH_SESSION_BLOCK_DIRECTIONS                          "libssh_session_block_directions"
//#define HRNLIBSSH_SESSION_DISCONNECT_EX                             "libssh_session_disconnect_ex"
//#define HRNLIBSSH_SESSION_FREE                                      "libssh_session_free"
//#define HRNLIBSSH_SESSION_HANDSHAKE                                 "libssh_session_handshake"
//#define HRNLIBSSH_SESSION_HOSTKEY                                   "libssh_session_hostkey"
//#define HRNLIBSSH_SESSION_INIT_EX                                   "libssh_session_init_ex"
//#define HRNLIBSSH_SESSION_LAST_ERRNO                                "libssh_session_last_errno"
//#define HRNLIBSSH_SESSION_LAST_ERROR                                "libssh_session_last_error"
//#define HRNLIBSSH_SFTP_CLOSE_HANDLE                                 "libssh_sftp_close_handle"
//#define HRNLIBSSH_SFTP_FSYNC                                        "libssh_sftp_fsync"
//#define HRNLIBSSH_SFTP_INIT                                         "libssh_sftp_init"
//#define HRNLIBSSH_SFTP_LAST_ERROR                                   "libssh_sftp_last_error"
//#define HRNLIBSSH_SFTP_MKDIR_EX                                     "libssh_sftp_mkdir_ex"
//#define HRNLIBSSH_SFTP_OPEN_EX                                      "libssh_sftp_open_ex"
//#define HRNLIBSSH_SFTP_READ                                         "libssh_sftp_read"
//#define HRNLIBSSH_SFTP_READDIR_EX                                   "libssh_sftp_readdir_ex"
//#define HRNLIBSSH_SFTP_RENAME_EX                                    "libssh_sftp_rename_ex"
//#define HRNLIBSSH_SFTP_RMDIR_EX                                     "libssh_sftp_rmdir_ex"
//#define HRNLIBSSH_SFTP_SEEK64                                       "libssh_sftp_seek64"
//#define HRNLIBSSH_SFTP_SHUTDOWN                                     "libssh_sftp_shutdown"
//#define HRNLIBSSH_SFTP_STAT_EX                                      "libssh_sftp_stat_ex"
//#define HRNLIBSSH_SFTP_SYMLINK_EX                                   "libssh_sftp_symlink_ex"
//#define HRNLIBSSH_SFTP_UNLINK_EX                                    "libssh_sftp_unlink_ex"
//#define HRNLIBSSH_SFTP_WRITE                                        "libssh_sftp_write"
//#define HRNLIBSSH_USERAUTH_PUBLICKEY_FROMFILE_EX                    "libssh_userauth_publickey_fromfile_ex"

///***********************************************************************************************************************************
//Macros for defining groups of functions that implement commands
//**********************************************************************************************************************************
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
//    uint64_t flags;                                                 // libssh flags
//    uint64_t attrPerms;                                             // libssh attr perms
//    uint64_t atime, mtime;                                          // libssh timestamps
//    uint64_t uid, gid;                                              // libssh uid/gid
//    uint64_t filesize;                                              // libssh filesize
//    uint64_t offset;                                                // libssh seek offset
//    const String *symlinkExTarget;                                  // libssh_sftp_symlink_ex target
//    const String *fileName;                                         // libssh_readdir* libssh_stat* filename
//    const String *readBuffer;                                       // what to copy into read buffer
//    TimeMSec sleep;                                                 // Sleep specified milliseconds before returning from function
//    size_t len;                                                     // libssh_session_hostkey len
//    int type;                                                       // libssh_session_hostkey type
    char *errMsg;                                                   // libssh_session_last_error error msg
} HrnLibSsh;

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
void hrnLibSshScriptSet(HrnLibSsh2 *hrnLibSshScriptParam);

#endif // HARNESS_LIBSSH_REAL

#endif // HAVE_LIBSSH

#endif // TEST_COMMON_HARNESS_LIBSSH_H
