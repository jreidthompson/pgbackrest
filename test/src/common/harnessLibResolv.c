/***********************************************************************************************************************************
libresolv Test Harness
***********************************************************************************************************************************/
#include "build.auto.h"

#ifdef HAVE_LIBRESOLV

#include <stdio.h>
#include <string.h>

#include "common/type/json.h"
#include "common/type/string.h"
#include "common/type/variantList.h"

#include "common/harnessLibResolv.h"
#include "common/harnessTest.h"

/***********************************************************************************************************************************
libresolv shim error prefix
***********************************************************************************************************************************/
#define LIBRESOLV_ERROR_PREFIX                                      "LIBRESOLV SHIM ERROR"

/***********************************************************************************************************************************
Script that defines how shim functions operate
***********************************************************************************************************************************/
HrnLibResolv hrnLibResolvScript[1024];
bool hrnLibResolvScriptDone = true;
unsigned int hrnLibResolvScriptIdx;

// If there is a script failure change the behavior of cleanup functions to return immediately so the real error will be reported
// rather than a bogus scripting error during cleanup
bool hrnLibResolvScriptFail;
char hrnLibResolvScriptError[4096];

/***********************************************************************************************************************************
Set libresolv script
***********************************************************************************************************************************/
void
hrnLibResolvScriptSet(HrnLibResolv *hrnLibResolvScriptParam)
{
    if (!hrnLibResolvScriptDone)
        THROW(AssertError, "previous libresolv script has not yet completed");

    if (hrnLibResolvScriptParam[0].function == NULL)
        THROW(AssertError, "libresolv script must have entries");

    // Copy records into local storage
    unsigned int copyIdx = 0;

    while (hrnLibResolvScriptParam[copyIdx].function != NULL)
    {
        hrnLibResolvScript[copyIdx] = hrnLibResolvScriptParam[copyIdx];
        copyIdx++;
    }

    hrnLibResolvScript[copyIdx].function = NULL;
    hrnLibResolvScriptDone = false;
    hrnLibResolvScriptIdx = 0;
}

/***********************************************************************************************************************************
Run libresolv script
***********************************************************************************************************************************/
static HrnLibResolv *
hrnLibResolvScriptRun(const char *const function, const VariantList *const param, const HrnLibResolv *const parent)
{
    // If an error has already been thrown then throw the same error again
    if (hrnLibResolvScriptFail)
        THROW(AssertError, hrnLibResolvScriptError);

    // Convert params to json for comparison and reporting
    String *paramStr = NULL;

    if (param)
    {
        Variant *const varList = varNewVarLst(param);

        paramStr = jsonFromVar(varList);
        varFree(varList);
    }
    else
        paramStr = strNew();

    // Ensure script has not ended
    if (hrnLibResolvScriptDone)
    {
        snprintf(
            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError), "libresolv script ended before %s (%s)", function,
            strZ(paramStr));

        TEST_LOG_FMT(LIBRESOLV_ERROR_PREFIX ": %s", hrnLibResolvScriptError);
        hrnLibResolvScriptFail = true;

        THROW(AssertError, hrnLibResolvScriptError);
    }

    // Get current script item
    HrnLibResolv *result = &hrnLibResolvScript[hrnLibResolvScriptIdx];

    // Check that expected function was called
    if (strcmp(result->function, function) != 0)
    {
        snprintf(
            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
            "libresolv script [%u] expected function %s (%s) but got %s (%s)", hrnLibResolvScriptIdx, result->function,
            result->param == NULL ? "" : result->param, function, strZ(paramStr));

        TEST_LOG_FMT(LIBRESOLV_ERROR_PREFIX ": %s", hrnLibResolvScriptError);
        hrnLibResolvScriptFail = true;

        THROW(AssertError, hrnLibResolvScriptError);
    }

    // Check that parameters match
    if ((param != NULL && result->param == NULL) || (param == NULL && result->param != NULL) ||
        (param != NULL && result->param != NULL && !strEqZ(paramStr, result->param)))
    {
        snprintf(
            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
            "libresolv script [%u] function '%s', expects param '%s' but got '%s'",
            hrnLibResolvScriptIdx, result->function, result->param ? result->param : "NULL", param ? strZ(paramStr) : "NULL");

        TEST_LOG_FMT(LIBRESOLV_ERROR_PREFIX ": %s", hrnLibResolvScriptError);
        hrnLibResolvScriptFail = true;

        THROW(AssertError, hrnLibResolvScriptError);
    }

    // Make sure the session matches with the parent as a sanity check
    if (parent != NULL && result->session != parent->session)
    {
        snprintf(
            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
            "libresolv script [%u] function '%s', expects session '%u' but got '%u'",
            hrnLibResolvScriptIdx, result->function, result->session, parent->session);

        TEST_LOG_FMT(LIBRESOLV_ERROR_PREFIX ": %s", hrnLibResolvScriptError);
        hrnLibResolvScriptFail = true;

        THROW(AssertError, hrnLibResolvScriptError);
    }

    // Sleep if requested
    if (result->sleep > 0)
        sleepMSec(result->sleep);

    hrnLibResolvScriptIdx++;

    if (hrnLibResolvScript[hrnLibResolvScriptIdx].function == NULL)
        hrnLibResolvScriptDone = true;

    strFree(paramStr);

    return result;
}

/***********************************************************************************************************************************
Shim for res_nquery
***********************************************************************************************************************************/
int
res_nquery(res_state statep, const char *dname, int class, int type, unsigned char *answer, int anslen)
{
    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(
        HRNLIBRESOLV_RES_NQUERY,
        varLstAdd(
            varLstAdd(
                varLstAdd(
                    varLstAdd(
                        varLstAdd(
                            varLstAdd(
                                varLstNew(), varNewStrZ(dname)),
                            varNewInt(class)),
                        varNewInt(type)),
                    varNewStrZ(answer)),
                varNewUInt64(anslen)),
            (HrnLibResolv *)statep);

    return hrnLibResolv->resultInt;
}

#endif // HAVE_LIBRESOLV
       //
// jrt remove all this
///***********************************************************************************************************************************
//Shim for libresolv_init
//***********************************************************************************************************************************/
//int
//libresolv_init(int flags)
//{
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(HRNLIBRESOLV_INIT, varLstAdd(varLstNew(), varNewInt(flags)), NULL);
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_addc
//***********************************************************************************************************************************/
//int
//libresolv_knownhost_addc(
//    LIBRESOLV_KNOWNHOSTS *hosts, const char *host, const char *salt, const char *key, size_t keylen, const char *comment,
//    size_t commentlen, int typemask, struct libresolv_knownhost **store)
//{
//    // Avoid compiler complaining of unused param
//    (void)store;
//
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
//            "libresolv script function 'libresolv_knownhost_adddc', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibResolvScriptError);
//    }
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_KNOWNHOST_ADDC,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstAdd(
//                                varLstAdd(
//                                    varLstAdd(
//                                        varLstNew(), varNewStrZ(host)),
//                                    varNewStrZ(salt)),
//                                varNewStrZ(key)),
//                            varNewUInt64(keylen)),
//                        varNewStrZ(comment)),
//                    varNewUInt64(commentlen)),
//                varNewInt(typemask)),
//            (HrnLibResolv *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_checkp
//***********************************************************************************************************************************/
//int
//libresolv_knownhost_checkp(
//    LIBRESOLV_KNOWNHOSTS *hosts, const char *host, int port, const char *key, size_t keylen, int typemask,
//    struct libresolv_knownhost **knownhost)
//{
//    // Avoid compiler complaining of unused param
//    (void)knownhost;
//
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
//            "libresolv script function 'libresolv_knownhost_checkp', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibResolvScriptError);
//    }
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_KNOWNHOST_CHECKP,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstAdd(
//                                varLstNew(), varNewStrZ(host)),
//                            varNewInt(port)),
//                        varNewStrZ(key)),
//                    varNewUInt64(keylen)),
//                varNewInt(typemask)),
//            (HrnLibResolv *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_free
//***********************************************************************************************************************************/
//void
//libresolv_knownhost_free(LIBRESOLV_KNOWNHOSTS *hosts)
//{
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
//            "libresolv script function 'libresolv_session_knownhost_free', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibResolvScriptError);
//    }
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_init
//***********************************************************************************************************************************/
//LIBRESOLV_KNOWNHOSTS *
//libresolv_knownhost_init(LIBRESOLV_SESSION *session)
//{
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(HRNLIBRESOLV_KNOWNHOST_INIT, NULL, (HrnLibResolv *)session);
//
//    return hrnLibResolv->resultNull ? NULL : (LIBRESOLV_KNOWNHOSTS *)hrnLibResolv;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_readfile
//***********************************************************************************************************************************/
//int
//libresolv_knownhost_readfile(LIBRESOLV_KNOWNHOSTS *hosts, const char *filename, int type)
//{
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_KNOWNHOST_READFILE,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(filename)),
//                varNewInt(type)),
//            (HrnLibResolv *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_knownhost_writefile
//***********************************************************************************************************************************/
//int
//libresolv_knownhost_writefile(LIBRESOLV_KNOWNHOSTS *hosts, const char *filename, int type)
//{
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_KNOWNHOST_WRITEFILE,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(filename)),
//                varNewInt(type)),
//            (HrnLibResolv *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_hostkey
//***********************************************************************************************************************************/
//const char *
//libresolv_session_hostkey(LIBRESOLV_SESSION *session, size_t *len, int *type)
//{
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(HRNLIBRESOLV_SESSION_HOSTKEY, NULL, (HrnLibResolv *)session);
//
//    *len = (size_t)hrnLibResolv->len;
//    *type = (int)hrnLibResolv->type;
//
//    return hrnLibResolv->resultNull ? NULL : (const char *)hrnLibResolv->resultZ;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_init
//***********************************************************************************************************************************/
//LIBRESOLV_SESSION *
//libresolv_session_init_ex(
//    LIBRESOLV_ALLOC_FUNC((*myalloc)), LIBRESOLV_FREE_FUNC((*myfree)), LIBRESOLV_REALLOC_FUNC((*myrealloc)), void *abstract)
//{
//    // All of these should always be the default NULL
//    if (myalloc != NULL && myfree != NULL && myrealloc != NULL && abstract != NULL)
//    {
//        snprintf(
//            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
//            "libresolv script function 'libresolv_session_init_ex', expects all params to be NULL");
//        THROW(AssertError, hrnLibResolvScriptError);
//    }
//
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(
//        HRNLIBRESOLV_SESSION_INIT_EX,
//        varLstAdd(
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewStr(NULL)),
//                    varNewStr(NULL)),
//                varNewStr(NULL)),
//            varNewStr(NULL)),
//        NULL);
//
//    return hrnLibResolv->resultNull ? NULL : (LIBRESOLV_SESSION *)hrnLibResolv;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_last_error
//***********************************************************************************************************************************/
//int
//libresolv_session_last_error(LIBRESOLV_SESSION *session, char **errmsg, int *errmsg_len, int want_buf)
//{
//    // Avoid compiler complaining of unused params
//    (void)errmsg_len;
//    (void)want_buf;
//
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(HRNLIBRESOLV_SESSION_LAST_ERROR, NULL, (HrnLibResolv *)session);
//
//    if (hrnLibResolv->errMsg != NULL)
//        *errmsg = hrnLibResolv->errMsg;
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_handshake
//***********************************************************************************************************************************/
//int
//libresolv_session_handshake(LIBRESOLV_SESSION *session, libresolv_socket_t sock)
//{
//    return hrnLibResolvScriptRun(
//        HRNLIBRESOLV_SESSION_HANDSHAKE, varLstAdd(varLstNew(), varNewInt(sock)), (HrnLibResolv *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_block_directions
//***********************************************************************************************************************************/
//int
//libresolv_session_block_directions(LIBRESOLV_SESSION *session)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SESSION_BLOCK_DIRECTIONS, NULL, (HrnLibResolv *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_hostkey_hash
//***********************************************************************************************************************************/
//const char *
//libresolv_hostkey_hash(LIBRESOLV_SESSION *session, int hash_type)
//{
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_HOSTKEY_HASH, varLstAdd(varLstNew(), varNewInt(hash_type)), (HrnLibResolv *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultNull ? NULL : (const char *)hrnLibResolv->resultZ;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_userauth_publickey_fromfile_ex
//***********************************************************************************************************************************/
//int
//libresolv_userauth_publickey_fromfile_ex(
//    LIBRESOLV_SESSION *session, const char *username, unsigned int ousername_len, const char *publickey, const char *privatekey,
//    const char *passphrase)
//{
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    if (privatekey == NULL)
//    {
//        snprintf(
//            hrnLibResolvScriptError, sizeof(hrnLibResolvScriptError),
//            "libresolv script function 'libresolv_userauth_publickey_fromfile_ex', expects privatekey to be not NULL");
//        THROW(AssertError, hrnLibResolvScriptError);
//    }
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_USERAUTH_PUBLICKEY_FROMFILE_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstAdd(
//                                varLstNew(), varNewStrZ(username)),
//                            varNewUInt(ousername_len)),
//                        varNewStrZ(publickey)),
//                    varNewStrZ(privatekey)),
//                varNewStrZ(passphrase)),
//            (HrnLibResolv *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_init
//***********************************************************************************************************************************/
//LIBRESOLV_SFTP *
//libresolv_sftp_init(LIBRESOLV_SESSION *session)
//{
//    HrnLibResolv *hrnLibResolv = hrnLibResolvScriptRun(HRNLIBRESOLV_SFTP_INIT, NULL, (HrnLibResolv *)session);
//
//    return hrnLibResolv->resultNull ? NULL : (LIBRESOLV_SFTP *)hrnLibResolv;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_close_handle
//***********************************************************************************************************************************/
//int
//libresolv_sftp_close_handle(LIBRESOLV_SFTP_HANDLE *handle)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SFTP_CLOSE_HANDLE, NULL, (HrnLibResolv *)handle)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_shutdown
//***********************************************************************************************************************************/
//int
//libresolv_sftp_shutdown(LIBRESOLV_SFTP *sftp)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SFTP_SHUTDOWN, NULL, (HrnLibResolv *)sftp)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_disconnect_ex
//***********************************************************************************************************************************/
//int
//libresolv_session_disconnect_ex(LIBRESOLV_SESSION *session, int reason, const char *description, const char *lang)
//{
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SESSION_DISCONNECT_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewInt(reason)),
//                    varNewStrZ(description)),
//                varNewStrZ(lang)),
//            (HrnLibResolv *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for int libresolv_session_free
//***********************************************************************************************************************************/
//int
//libresolv_session_free(LIBRESOLV_SESSION *session)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SESSION_FREE, NULL, (HrnLibResolv *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_stat_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_stat_ex(
//    LIBRESOLV_SFTP *sftp, const char *path, unsigned int path_len, int stat_type, LIBRESOLV_SFTP_ATTRIBUTES *attrs)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    //
//    // Could we utilize test.c/build.c to calculate/define this and other length params?
//    (void)path_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_STAT_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(path)),
//                varNewInt(stat_type)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    if (attrs == NULL)
//        THROW(AssertError, "attrs is NULL");
//
//    attrs->flags = 0;
//    attrs->flags |= (unsigned long)hrnLibResolv->flags;
//
//    attrs->permissions = 0;
//    attrs->permissions |= (unsigned long)hrnLibResolv->attrPerms;
//
//    attrs->mtime = (unsigned long)hrnLibResolv->mtime;
//    attrs->uid = (unsigned long)hrnLibResolv->uid;
//    attrs->gid = (unsigned long)hrnLibResolv->gid;
//    attrs->filesize = hrnLibResolv->filesize;
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_last_error
//***********************************************************************************************************************************/
//unsigned long
//libresolv_sftp_last_error(LIBRESOLV_SFTP *sftp)
//{
//    return (unsigned long)hrnLibResolvScriptRun(HRNLIBRESOLV_SFTP_LAST_ERROR, NULL, (HrnLibResolv *)sftp)->resultUInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_symlink_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_symlink_ex(
//    LIBRESOLV_SFTP *sftp, const char *path, unsigned int path_len, char *target, unsigned int target_len, int link_type)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)path_len;
//    (void)target_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_SYMLINK_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewStrZ(path)),
//                    varNewStrZ(target)),
//                varNewInt(link_type)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    int rc;
//
//    switch (link_type)
//    {
//        case LIBRESOLV_SFTP_READLINK:
//        case LIBRESOLV_SFTP_REALPATH:
//            if (hrnLibResolv->symlinkExTarget != NULL)
//            {
//                if (strSize(hrnLibResolv->symlinkExTarget) < PATH_MAX)
//                    strncpy(target, strZ(hrnLibResolv->symlinkExTarget), strSize(hrnLibResolv->symlinkExTarget));
//                else
//                    THROW_FMT(AssertError, "symlinkExTarget too large for target buffer");
//            }
//
//            rc = hrnLibResolv->resultInt != 0 ? hrnLibResolv->resultInt : (int)strSize(hrnLibResolv->symlinkExTarget);
//            break;
//
//        default:
//            THROW_FMT(AssertError, "UNKNOWN link_type");
//            break;
//    }
//
//    return rc;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_open_ex
//***********************************************************************************************************************************/
//LIBRESOLV_SFTP_HANDLE *
//libresolv_sftp_open_ex(
//    LIBRESOLV_SFTP *sftp, const char *filename, unsigned int filename_len, unsigned long flags, long mode, int open_type)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)filename_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_OPEN_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstNew(), varNewStrZ(filename)),
//                        varNewUInt64(flags)),
//                    varNewInt64(mode)),
//                varNewInt(open_type)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultNull ? NULL : (LIBRESOLV_SFTP_HANDLE *)hrnLibResolv;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_readdir_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_readdir_ex(
//    LIBRESOLV_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen, char *longentry, size_t longentry_maxlen,
//    LIBRESOLV_SFTP_ATTRIBUTES *attrs)
//{
//    if (attrs == NULL)
//        THROW_FMT(AssertError, "attrs is NULL");
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_READDIR_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstNew(), varNewStrZ(buffer)),
//                        varNewUInt64(buffer_maxlen)),
//                    varNewStrZ(longentry)),
//                varNewUInt64(longentry_maxlen)),
//            (HrnLibResolv *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    if (hrnLibResolv->fileName != NULL)
//        strncpy(buffer, strZ(hrnLibResolv->fileName), buffer_maxlen);
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_session_last_errno
//***********************************************************************************************************************************/
//int
//libresolv_session_last_errno(LIBRESOLV_SESSION *session)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SESSION_LAST_ERRNO, NULL, (HrnLibResolv *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_fsync
//***********************************************************************************************************************************/
//int
//libresolv_sftp_fsync(LIBRESOLV_SFTP_HANDLE *handle)
//{
//    return hrnLibResolvScriptRun(HRNLIBRESOLV_SFTP_FSYNC, NULL, (HrnLibResolv *)handle)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_mkdir_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_mkdir_ex(LIBRESOLV_SFTP *sftp, const char *path, unsigned int path_len, long mode)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on
//    // where tests are being run.
//    (void)path_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_MKDIR_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(path)),
//                varNewInt64(mode)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_read
//***********************************************************************************************************************************/
//ssize_t
//libresolv_sftp_read(LIBRESOLV_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen)
//{
//    // We don't pass buffer to hrnLibResolvScriptRun. The first call for each invocation passes buffer with random data, which is
//    // an issue for sftpTest.c.
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_READ,
//            varLstAdd(
//                varLstNew(), varNewUInt64(buffer_maxlen)),
//            (HrnLibResolv *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    // copy read into buffer
//    if (hrnLibResolv->readBuffer != NULL)
//        strncpy(buffer, strZ(hrnLibResolv->readBuffer), strSize(hrnLibResolv->readBuffer));
//
//    // number of bytes populated
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_rename_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_rename_ex(
//    LIBRESOLV_SFTP *sftp, const char *source_filename, unsigned int source_filename_len, const char *dest_filename,
//    unsigned int dest_filename_len, long flags)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on
//    // where tests are being run.
//    (void)source_filename_len;
//    (void)dest_filename_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_RENAME_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewStrZ(source_filename)),
//                    varNewStrZ(dest_filename)),
//                varNewInt64(flags)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_rmdir_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_rmdir_ex(LIBRESOLV_SFTP *sftp, const char *path, unsigned int path_len)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)path_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_RMDIR_EX,
//            varLstAdd(
//                varLstNew(), varNewStrZ(path)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_seek64
//***********************************************************************************************************************************/
//void
//libresolv_sftp_seek64(LIBRESOLV_SFTP_HANDLE *handle, libresolv_uint64_t offset)
//{
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_SEEK64,
//            varLstAdd(
//                varLstNew(), varNewUInt64(offset)),
//            (HrnLibResolv *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_unlink_ex
//***********************************************************************************************************************************/
//int
//libresolv_sftp_unlink_ex(LIBRESOLV_SFTP *sftp, const char *filename, unsigned int filename_len)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibResolvScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)filename_len;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_UNLINK_EX,
//            varLstAdd(
//                varLstNew(), varNewStrZ(filename)),
//            (HrnLibResolv *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibResolv->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libresolv_sftp_write
//***********************************************************************************************************************************/
//ssize_t
//libresolv_sftp_write(LIBRESOLV_SFTP_HANDLE *handle, const char *buffer, size_t count)
//{
//    // We don't pass buffer to hrnLibResolvScriptRun. The first call for each invocation passes buffer with random data, which is
//    // an issue for sftpTest.c.
//    (void)buffer;
//
//    HrnLibResolv *hrnLibResolv = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibResolv = hrnLibResolvScriptRun(
//            HRNLIBRESOLV_SFTP_WRITE,
//            varLstAdd(
//                varLstNew(), varNewUInt64(count)),
//            (HrnLibResolv *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    // Return number of bytes written
//    return hrnLibResolv->resultInt;
//}
