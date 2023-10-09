/***********************************************************************************************************************************
libresolv Test Harness

Scripted testing for libresolv so exact results can be returned for unit testing. See sftp unit tests for usage examples.
***********************************************************************************************************************************/
#ifndef TEST_COMMON_HARNESS_LIBRESOLV_H
#define TEST_COMMON_HARNESS_LIBRESOLV_H

#ifdef HAVE_LIBRESOLV

#ifndef HARNESS_LIBRESOLV_REAL

#include <resolv.h>
#include <stdbool.h>

#include "common/macro.h"
#include "common/time.h"
#include "version.h"

/***********************************************************************************************************************************
libresolv authorization constants
***********************************************************************************************************************************/
//#define HOSTKEY                                                     "12345678901234567890"

/***********************************************************************************************************************************
Function constants
***********************************************************************************************************************************/
#define HRNLIBRESOLV_RES_NQUERY                                     "res_nquery"

/***********************************************************************************************************************************
Macros for defining groups of functions that implement commands
***********************************************************************************************************************************/

/***********************************************************************************************************************************
Structure for scripting libresolv responses
***********************************************************************************************************************************/
typedef struct HrnLibResolv
{
    unsigned int session;                                           // Session number when multiple sessions are run concurrently
    const char *function;                                           // Function call expected
    const char *param;                                              // Params expected by the function for verification
    int resultInt;                                                  // Int result value
    uint64_t resultUInt;                                            // UInt result value
    const char *resultZ;                                            // Zero-terminated result value
    bool resultNull;                                                // Return null from function that normally returns a struct ptr
    size_t len;                                                     // libresolv_session_hostkey len
//    uint64_t flags;                                                 // libresolv flags
//    uint64_t attrPerms;                                             // libresolv attr perms
//    uint64_t atime, mtime;                                          // libresolv timestamps
//    uint64_t uid, gid;                                              // libresolv uid/gid
//    uint64_t filesize;                                              // libresolv filesize
//    uint64_t offset;                                                // libresolv seek offset
//    const String *symlinkExTarget;                                  // libresolv_sftp_symlink_ex target
//    const String *fileName;                                         // libresolv_readdir* libresolv_stat* filename
//    const String *readBuffer;                                       // what to copy into read buffer
//    TimeMSec sleep;                                                 // Sleep specified milliseconds before returning from function
//    int type;                                                       // libresolv_session_hostkey type
//    char *errMsg;                                                   // libresolv_session_last_error error msg
} HrnLibResolv;

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
void hrnLibResolvScriptSet(HrnLibResolv *hrnLibResolvScriptParam);

#endif // HARNESS_LIBRESOLV_REAL

#endif // HAVE_LIBRESOLV

#endif // TEST_COMMON_HARNESS_LIBRESOLV_H
