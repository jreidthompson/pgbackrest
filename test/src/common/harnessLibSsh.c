/***********************************************************************************************************************************
libssh Test Harness
***********************************************************************************************************************************/
#include "build.auto.h"

#ifdef HAVE_LIBSSH

#include <stdio.h>
#include <string.h>

#include "common/type/json.h"
#include "common/type/string.h"
#include "common/type/variantList.h"

#include "common/harnessLibSsh.h"
#include "common/harnessTest.h"

/***********************************************************************************************************************************
libssh shim error prefix
***********************************************************************************************************************************/
#define LIBSSH_ERROR_PREFIX                                         "LIBSSH SHIM ERROR"

/***********************************************************************************************************************************
Script that defines how shim functions operate
***********************************************************************************************************************************/
HrnLibSsh hrnLibSshScript[1024];
bool hrnLibSshScriptDone = true;
unsigned int hrnLibSshScriptIdx;

// If there is a script failure change the behavior of cleanup functions to return immediately so the real error will be reported
// rather than a bogus scripting error during cleanup
bool hrnLibSshScriptFail;
char hrnLibSshScriptError[4096];

/***********************************************************************************************************************************
Set libssh script
***********************************************************************************************************************************/
void
hrnLibSshScriptSet(HrnLibSsh *hrnLibSshScriptParam)
{
    if (!hrnLibSshScriptDone)
        THROW(AssertError, "previous libssh script has not yet completed");

    if (hrnLibSshScriptParam[0].function == NULL)
        THROW(AssertError, "libssh script must have entries");

    // Copy records into local storage
    unsigned int copyIdx = 0;

    while (hrnLibSshScriptParam[copyIdx].function != NULL)
    {
        hrnLibSshScript[copyIdx] = hrnLibSshScriptParam[copyIdx];
        copyIdx++;
    }

    hrnLibSshScript[copyIdx].function = NULL;
    hrnLibSshScriptDone = false;
    hrnLibSshScriptIdx = 0;
}

/***********************************************************************************************************************************
Run libssh script
***********************************************************************************************************************************/
static HrnLibSsh *
hrnLibSshScriptRun(const char *const function, const VariantList *const param, const HrnLibSsh *const parent)
{
    // If an error has already been thrown then throw the same error again
    if (hrnLibSshScriptFail)
        THROW(AssertError, hrnLibSshScriptError);

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
    if (hrnLibSshScriptDone)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError), "libssh script ended before %s (%s)", function,
            strZ(paramStr));

        TEST_LOG_FMT(LIBSSH_ERROR_PREFIX ": %s", hrnLibSshScriptError);
        hrnLibSshScriptFail = true;

        THROW(AssertError, hrnLibSshScriptError);
    }

    // Get current script item
    HrnLibSsh *result = &hrnLibSshScript[hrnLibSshScriptIdx];

    // Check that expected function was called
    if (strcmp(result->function, function) != 0)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script [%u] expected function %s (%s) but got %s (%s)", hrnLibSshScriptIdx, result->function,
            result->param == NULL ? "" : result->param, function, strZ(paramStr));

        TEST_LOG_FMT(LIBSSH_ERROR_PREFIX ": %s", hrnLibSshScriptError);
        hrnLibSshScriptFail = true;

        THROW(AssertError, hrnLibSshScriptError);
    }

    // Check that parameters match
    if ((param != NULL && result->param == NULL) || (param == NULL && result->param != NULL) ||
        (param != NULL && result->param != NULL && !strEqZ(paramStr, result->param)))
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script [%u] function '%s', expects param '%s' but got '%s'",
            hrnLibSshScriptIdx, result->function, result->param ? result->param : "NULL", param ? strZ(paramStr) : "NULL");

        TEST_LOG_FMT(LIBSSH_ERROR_PREFIX ": %s", hrnLibSshScriptError);
        hrnLibSshScriptFail = true;

        THROW(AssertError, hrnLibSshScriptError);
    }

    // Make sure the session matches with the parent as a sanity check
    if (parent != NULL && result->session != parent->session)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script [%u] function '%s', expects session '%u' but got '%u'",
            hrnLibSshScriptIdx, result->function, result->session, parent->session);

        TEST_LOG_FMT(LIBSSH_ERROR_PREFIX ": %s", hrnLibSshScriptError);
        hrnLibSshScriptFail = true;

        THROW(AssertError, hrnLibSshScriptError);
    }

    // Sleep if requested
    if (result->sleep > 0)
        sleepMSec(result->sleep);

    hrnLibSshScriptIdx++;

    if (hrnLibSshScript[hrnLibSshScriptIdx].function == NULL)
        hrnLibSshScriptDone = true;

    strFree(paramStr);

    return result;
}

/***********************************************************************************************************************************
Shim for ssh_new
***********************************************************************************************************************************/
ssh_session
ssh_new()
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_NEW, NULL, NULL);

//    return hrnLibSshScriptRun(HRNLIBSSH_INIT, NULL, (HrnLibSsh *)session)->resultInt;
//    return hrnLibSsh->resultInt;
    return hrnLibSsh->resultNull ? NULL : (ssh_session)hrnLibSsh;
}

/***********************************************************************************************************************************
Shim for ssh_free
***********************************************************************************************************************************/
void
ssh_free(ssh_session session)
{
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_FREE, NULL, (HrnLibSsh *)session);

    if (session == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'ssh_free', expects session to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }

//    if (hrnLibSsh->resultInt != SSH_OK)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'ssh_free', expects resultInt to be SSH_OK");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
}

/***********************************************************************************************************************************
Shim for ssh_options_set
***********************************************************************************************************************************/
int
ssh_options_set(ssh_session session, enum ssh_options_e type, const void *value)
{
    HrnLibSsh *hrnLibSsh = NULL;
    //(void)value;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        switch (type)
        {
            case SSH_OPTIONS_PORT:
            case SSH_OPTIONS_FD:
            {
                hrnLibSsh = hrnLibSshScriptRun(
                    HRNLIBSSH_OPTIONS_SET,
                    varLstAdd(
                        varLstAdd(
                            varLstNew(), varNewInt(type)),
                        varNewInt(*((int*)value))),
                    (HrnLibSsh *)session);
                break;
            }
            case SSH_OPTIONS_USER:
            case SSH_OPTIONS_HOST:
            {
                hrnLibSsh = hrnLibSshScriptRun(
                    HRNLIBSSH_OPTIONS_SET,
                    varLstAdd(
                        varLstAdd(
                            varLstNew(), varNewInt(type)),
                        varNewStrZ((const char *)value)),
                    (HrnLibSsh *)session);
                break;
            }
            default:
            {
            }
        }
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_connect
***********************************************************************************************************************************/
int
ssh_connect(ssh_session session)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_CONNECT, NULL, (HrnLibSsh *)session);

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_disconnect
***********************************************************************************************************************************/
void
ssh_disconnect(ssh_session session)
{
    if (session == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'ssh_disconnect', expects session to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }
}

/***********************************************************************************************************************************
Shim for ssh_get_server_publickey
***********************************************************************************************************************************/
int
ssh_get_server_publickey(ssh_session session, ssh_key *key)
{
    (void)key; // Avoid compiler complaining of unused param

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_GET_SERVER_PUBLICKEY, NULL, (HrnLibSsh *)session);

    // jrt remove this if we don't use it in the tests anywhere
    // Hack the key 
    //*(key) = (ssh_key)hrnLibSsh->resultZ;

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_key_free
***********************************************************************************************************************************/
void
ssh_key_free(ssh_key key)
{
    if (key == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'ssh_key_free', expects key to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }
}

/***********************************************************************************************************************************
Shim for ssh_get_publickey_hash
***********************************************************************************************************************************/
int
ssh_get_publickey_hash(const ssh_key key, enum ssh_publickey_hash_type type, unsigned char ** hash, size_t * hlen)
{
    (void)key; // Avoid compiler complaining of unused param

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_GET_PUBLICKEY_HASH, NULL, NULL);

    (void) type;
    //type = (int)hrnLibSsh->type;
    *hlen = (size_t)hrnLibSsh->len;
    *hash = (unsigned char *)hrnLibSsh->resultZ;

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_get_publickey_hash
***********************************************************************************************************************************/
char *
ssh_get_fingerprint_hash(enum ssh_publickey_hash_type type, unsigned char *hash, size_t len)
{
    (void) type; // Avoid compiler complaining of unused param
    (void) hash;
    (void) len;

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_GET_FINGERPRINT_HASH, NULL, NULL);

    return hrnLibSsh->resultNull ? NULL : (char *)hrnLibSsh->resultZ;
}

/***********************************************************************************************************************************
Shim for ssh_clean_pubkey_hash
***********************************************************************************************************************************/
void
ssh_clean_pubkey_hash(unsigned char **hash)
{
    if (hash == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'ssh_clean_pubkey_hash', expects hash to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }
}

///***********************************************************************************************************************************
//Shim for ssh_knownhost_addc
//***********************************************************************************************************************************/
//int
//ssh_knownhost_addc(
//    LIBSSH_KNOWNHOSTS *hosts, const char *host, const char *salt, const char *key, size_t keylen, const char *comment,
//    size_t commentlen, int typemask, struct ssh_knownhost **store)
//{
//    // Avoid compiler complaining of unused param
//    (void)store;
//
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'libssh_knownhost_adddc', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_KNOWNHOST_ADDC,
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
//            (HrnLibSsh *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for ssh_knownhost_checkp
//***********************************************************************************************************************************/
//int
//ssh_knownhost_checkp(
//    LIBSSH_KNOWNHOSTS *hosts, const char *host, int port, const char *key, size_t keylen, int typemask,
//    struct ssh_knownhost **knownhost)
//{
//    // Avoid compiler complaining of unused param
//    (void)knownhost;
//
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'libssh_knownhost_checkp', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_KNOWNHOST_CHECKP,
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
//            (HrnLibSsh *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for ssh_knownhost_free
//***********************************************************************************************************************************/
//void
//ssh_knownhost_free(LIBSSH_KNOWNHOSTS *hosts)
//{
//    if (hosts == NULL)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'libssh_session_knownhost_free', expects hosts to be not NULL");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
//}
//
///***********************************************************************************************************************************
//Shim for ssh_knownhost_init
//***********************************************************************************************************************************/
//SSH_KNOWNHOSTS *
//libssh_knownhost_init(LIBSSH_SESSION *session)
//{
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_KNOWNHOST_INIT, NULL, (HrnLibSsh *)session);
//
//    return hrnLibSsh->resultNull ? NULL : (LIBSSH_KNOWNHOSTS *)hrnLibSsh;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_knownhost_readfile
//***********************************************************************************************************************************/
//int
//libssh_knownhost_readfile(LIBSSH_KNOWNHOSTS *hosts, const char *filename, int type)
//{
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_KNOWNHOST_READFILE,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(filename)),
//                varNewInt(type)),
//            (HrnLibSsh *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_knownhost_writefile
//***********************************************************************************************************************************/
//int
//libssh_knownhost_writefile(LIBSSH_KNOWNHOSTS *hosts, const char *filename, int type)
//{
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_KNOWNHOST_WRITEFILE,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(filename)),
//                varNewInt(type)),
//            (HrnLibSsh *)hosts);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_hostkey
//***********************************************************************************************************************************/
//const char *
//libssh_session_hostkey(LIBSSH_SESSION *session, size_t *len, int *type)
//{
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SESSION_HOSTKEY, NULL, (HrnLibSsh *)session);
//
//    *len = (size_t)hrnLibSsh->len;
//    *type = (int)hrnLibSsh->type;
//
//    return hrnLibSsh->resultNull ? NULL : (const char *)hrnLibSsh->resultZ;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_init
//***********************************************************************************************************************************/
//LIBSSH_SESSION *
//libssh_session_init_ex(
//    LIBSSH_ALLOC_FUNC((*myalloc)), LIBSSH_FREE_FUNC((*myfree)), LIBSSH_REALLOC_FUNC((*myrealloc)), void *abstract)
//{
//    // All of these should always be the default NULL
//    if (myalloc != NULL && myfree != NULL && myrealloc != NULL && abstract != NULL)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'libssh_session_init_ex', expects all params to be NULL");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
//
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(
//        HRNLIBSSH_SESSION_INIT_EX,
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
//    return hrnLibSsh->resultNull ? NULL : (LIBSSH_SESSION *)hrnLibSsh;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_last_error
//***********************************************************************************************************************************/
//int
//libssh_session_last_error(LIBSSH_SESSION *session, char **errmsg, int *errmsg_len, int want_buf)
//{
//    // Avoid compiler complaining of unused params
//    (void)want_buf;
//
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SESSION_LAST_ERROR, NULL, (HrnLibSsh *)session);
//
//    if (hrnLibSsh->errMsg != NULL)
//    {
//        *errmsg = hrnLibSsh->errMsg;
//        *errmsg_len = (int)(strlen(hrnLibSsh->errMsg) + 1);
//    }
//    else
//    {
//        *errmsg = NULL;
//        *errmsg_len = 0;
//    }
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_handshake
//***********************************************************************************************************************************/
//int
//libssh_session_handshake(LIBSSH_SESSION *session, libssh_socket_t sock)
//{
//    return hrnLibSshScriptRun(
//        HRNLIBSSH_SESSION_HANDSHAKE, varLstAdd(varLstNew(), varNewInt(sock)), (HrnLibSsh *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_block_directions
//***********************************************************************************************************************************/
//int
//libssh_session_block_directions(LIBSSH_SESSION *session)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SESSION_BLOCK_DIRECTIONS, NULL, (HrnLibSsh *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_hostkey_hash
//***********************************************************************************************************************************/
//const char *
//libssh_hostkey_hash(LIBSSH_SESSION *session, int hash_type)
//{
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_HOSTKEY_HASH, varLstAdd(varLstNew(), varNewInt(hash_type)), (HrnLibSsh *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultNull ? NULL : (const char *)hrnLibSsh->resultZ;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_userauth_publickey_fromfile_ex
//***********************************************************************************************************************************/
//int
//libssh_userauth_publickey_fromfile_ex(
//    LIBSSH_SESSION *session, const char *username, unsigned int ousername_len, const char *publickey, const char *privatekey,
//    const char *passphrase)
//{
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    if (privatekey == NULL)
//    {
//        snprintf(
//            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
//            "libssh script function 'libssh_userauth_publickey_fromfile_ex', expects privatekey to be not NULL");
//        THROW(AssertError, hrnLibSshScriptError);
//    }
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_USERAUTH_PUBLICKEY_FROMFILE_EX,
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
//            (HrnLibSsh *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_init
//***********************************************************************************************************************************/
//LIBSSH_SFTP *
//libssh_sftp_init(LIBSSH_SESSION *session)
//{
//    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SFTP_INIT, NULL, (HrnLibSsh *)session);
//
//    return hrnLibSsh->resultNull ? NULL : (LIBSSH_SFTP *)hrnLibSsh;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_close_handle
//***********************************************************************************************************************************/
//int
//libssh_sftp_close_handle(LIBSSH_SFTP_HANDLE *handle)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_CLOSE_HANDLE, NULL, (HrnLibSsh *)handle)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_shutdown
//***********************************************************************************************************************************/
//int
//libssh_sftp_shutdown(LIBSSH_SFTP *sftp)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_SHUTDOWN, NULL, (HrnLibSsh *)sftp)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_disconnect_ex
//***********************************************************************************************************************************/
//int
//libssh_session_disconnect_ex(LIBSSH_SESSION *session, int reason, const char *description, const char *lang)
//{
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SESSION_DISCONNECT_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewInt(reason)),
//                    varNewStrZ(description)),
//                varNewStrZ(lang)),
//            (HrnLibSsh *)session);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for int libssh_session_free
//***********************************************************************************************************************************/
//int
//libssh_session_free(LIBSSH_SESSION *session)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SESSION_FREE, NULL, (HrnLibSsh *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_stat_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_stat_ex(
//    LIBSSH_SFTP *sftp, const char *path, unsigned int path_len, int stat_type, LIBSSH_SFTP_ATTRIBUTES *attrs)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    //
//    // Could we utilize test.c/build.c to calculate/define this and other length params?
//    (void)path_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_STAT_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(path)),
//                varNewInt(stat_type)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    if (attrs == NULL)
//        THROW(AssertError, "attrs is NULL");
//
//    attrs->flags = 0;
//    attrs->flags |= (unsigned long)hrnLibSsh->flags;
//
//    attrs->permissions = 0;
//    attrs->permissions |= (unsigned long)hrnLibSsh->attrPerms;
//
//    attrs->mtime = (unsigned long)hrnLibSsh->mtime;
//    attrs->uid = (unsigned long)hrnLibSsh->uid;
//    attrs->gid = (unsigned long)hrnLibSsh->gid;
//    attrs->filesize = hrnLibSsh->filesize;
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_last_error
//***********************************************************************************************************************************/
//unsigned long
//libssh_sftp_last_error(LIBSSH_SFTP *sftp)
//{
//    return (unsigned long)hrnLibSshScriptRun(HRNLIBSSH_SFTP_LAST_ERROR, NULL, (HrnLibSsh *)sftp)->resultUInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_symlink_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_symlink_ex(
//    LIBSSH_SFTP *sftp, const char *path, unsigned int path_len, char *target, unsigned int target_len, int link_type)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)path_len;
//    (void)target_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_SYMLINK_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewStrZ(path)),
//                    varNewStrZ(target)),
//                varNewInt(link_type)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    int rc;
//
//    switch (link_type)
//    {
//        case LIBSSH_SFTP_READLINK:
//        case LIBSSH_SFTP_REALPATH:
//            if (hrnLibSsh->symlinkExTarget != NULL)
//            {
//                if (strSize(hrnLibSsh->symlinkExTarget) < PATH_MAX)
//                    strncpy(target, strZ(hrnLibSsh->symlinkExTarget), strSize(hrnLibSsh->symlinkExTarget));
//                else
//                    THROW_FMT(AssertError, "symlinkExTarget too large for target buffer");
//            }
//
//            rc = hrnLibSsh->resultInt != 0 ? hrnLibSsh->resultInt : (int)strSize(hrnLibSsh->symlinkExTarget);
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
//Shim for libssh_sftp_open_ex
//***********************************************************************************************************************************/
//LIBSSH_SFTP_HANDLE *
//libssh_sftp_open_ex(
//    LIBSSH_SFTP *sftp, const char *filename, unsigned int filename_len, unsigned long flags, long mode, int open_type)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)filename_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_OPEN_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstNew(), varNewStrZ(filename)),
//                        varNewUInt64(flags)),
//                    varNewInt64(mode)),
//                varNewInt(open_type)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultNull ? NULL : (LIBSSH_SFTP_HANDLE *)hrnLibSsh;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_readdir_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_readdir_ex(
//    LIBSSH_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen, char *longentry, size_t longentry_maxlen,
//    LIBSSH_SFTP_ATTRIBUTES *attrs)
//{
//    if (attrs == NULL)
//        THROW_FMT(AssertError, "attrs is NULL");
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_READDIR_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstAdd(
//                            varLstNew(), varNewStrZ(buffer)),
//                        varNewUInt64(buffer_maxlen)),
//                    varNewStrZ(longentry)),
//                varNewUInt64(longentry_maxlen)),
//            (HrnLibSsh *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    if (hrnLibSsh->fileName != NULL)
//        strncpy(buffer, strZ(hrnLibSsh->fileName), buffer_maxlen);
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_session_last_errno
//***********************************************************************************************************************************/
//int
//libssh_session_last_errno(LIBSSH_SESSION *session)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SESSION_LAST_ERRNO, NULL, (HrnLibSsh *)session)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_fsync
//***********************************************************************************************************************************/
//int
//libssh_sftp_fsync(LIBSSH_SFTP_HANDLE *handle)
//{
//    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_FSYNC, NULL, (HrnLibSsh *)handle)->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_mkdir_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_mkdir_ex(LIBSSH_SFTP *sftp, const char *path, unsigned int path_len, long mode)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)path_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_MKDIR_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstNew(), varNewStrZ(path)),
//                varNewInt64(mode)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_read
//***********************************************************************************************************************************/
//ssize_t
//libssh_sftp_read(LIBSSH_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen)
//{
//    // We don't pass buffer to hrnLibSshScriptRun. The first call for each invocation passes buffer with random data, which is
//    // an issue for sftpTest.c.
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_READ,
//            varLstAdd(
//                varLstNew(), varNewUInt64(buffer_maxlen)),
//            (HrnLibSsh *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    // copy read into buffer
//    if (hrnLibSsh->readBuffer != NULL)
//        strncpy(buffer, strZ(hrnLibSsh->readBuffer), strSize(hrnLibSsh->readBuffer));
//
//    // number of bytes populated
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_rename_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_rename_ex(
//    LIBSSH_SFTP *sftp, const char *source_filename, unsigned int source_filename_len, const char *dest_filename,
//    unsigned int dest_filename_len, long flags)
//{
//    // To avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)source_filename_len;
//    (void)dest_filename_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_RENAME_EX,
//            varLstAdd(
//                varLstAdd(
//                    varLstAdd(
//                        varLstNew(), varNewStrZ(source_filename)),
//                    varNewStrZ(dest_filename)),
//                varNewInt64(flags)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_rmdir_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_rmdir_ex(LIBSSH_SFTP *sftp, const char *path, unsigned int path_len)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)path_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_RMDIR_EX,
//            varLstAdd(
//                varLstNew(), varNewStrZ(path)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_seek64
//***********************************************************************************************************************************/
//void
//libssh_sftp_seek64(LIBSSH_SFTP_HANDLE *handle, libssh_uint64_t offset)
//{
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_SEEK64,
//            varLstAdd(
//                varLstNew(), varNewUInt64(offset)),
//            (HrnLibSsh *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_unlink_ex
//***********************************************************************************************************************************/
//int
//libssh_sftp_unlink_ex(LIBSSH_SFTP *sftp, const char *filename, unsigned int filename_len)
//{
//    // Avoid compiler complaining of unused param. Not passing to hrnLibSshScriptRun, as parameter will vary depending on where
//    // tests are being run.
//    (void)filename_len;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_UNLINK_EX,
//            varLstAdd(
//                varLstNew(), varNewStrZ(filename)),
//            (HrnLibSsh *)sftp);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    return hrnLibSsh->resultInt;
//}
//
///***********************************************************************************************************************************
//Shim for libssh_sftp_write
//***********************************************************************************************************************************/
//ssize_t
//libssh_sftp_write(LIBSSH_SFTP_HANDLE *handle, const char *buffer, size_t count)
//{
//    // We don't pass buffer to hrnLibSshScriptRun. The first call for each invocation passes buffer with random data, which is
//    // an issue for sftpTest.c.
//    (void)buffer;
//
//    HrnLibSsh *hrnLibSsh = NULL;
//
//    MEM_CONTEXT_TEMP_BEGIN()
//    {
//        hrnLibSsh = hrnLibSshScriptRun(
//            HRNLIBSSH_SFTP_WRITE,
//            varLstAdd(
//                varLstNew(), varNewUInt64(count)),
//            (HrnLibSsh *)handle);
//    }
//    MEM_CONTEXT_TEMP_END();
//
//    // Return number of bytes written
//    return hrnLibSsh->resultInt;
//}

#endif // HAVE_LIBSSH
