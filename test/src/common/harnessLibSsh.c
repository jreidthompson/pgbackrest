/***********************************************************************************************************************************
libssh Test Harness
***********************************************************************************************************************************/
#include "build.auto.h"

#ifdef HAVE_LIBSSH

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
}

/***********************************************************************************************************************************
Shim for ssh_options_set
***********************************************************************************************************************************/
int
ssh_options_set(ssh_session session, enum ssh_options_e type, const void *value)
{
    HrnLibSsh *hrnLibSsh = NULL;

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
            case SSH_OPTIONS_KNOWNHOSTS:
            case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
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
Shim for ssh_options_get
***********************************************************************************************************************************/
int
ssh_options_get(ssh_session session, enum ssh_options_e type, char **value)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_OPTIONS_GET, NULL, (HrnLibSsh *)session);

    switch(type)
    {
        case SSH_OPTIONS_KNOWNHOSTS:
        case SSH_OPTIONS_GLOBAL_KNOWNHOSTS:
        {
                *(value) = (char *)hrnLibSsh->resultZ;
                break;
        }
        default:
        {
            break;
        }
    }

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_connect
***********************************************************************************************************************************/
int
ssh_connect(ssh_session session)
{
    return hrnLibSshScriptRun(HRNLIBSSH_CONNECT, NULL, (HrnLibSsh *)session)->resultInt;
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

    char *fingerprint = NULL;;

    if (!hrnLibSsh->resultNull)
    {
        fingerprint = malloc(512);
        strcpy(fingerprint, hrnLibSsh->resultZ);
    }

    return hrnLibSsh->resultNull ? NULL : fingerprint;
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

/***********************************************************************************************************************************
Shim for ssh_session_is_known_server
***********************************************************************************************************************************/
enum ssh_known_hosts_e
ssh_session_is_known_server(ssh_session session)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SESSION_IS_KNOWN_SERVER, NULL, (HrnLibSsh *)session);

    return (enum ssh_known_hosts_e)hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_get_error
***********************************************************************************************************************************/
const char *
ssh_get_error(void *error)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_GET_ERROR, NULL, (HrnLibSsh *)error);

    return hrnLibSsh->resultNull ? NULL : (const char *)hrnLibSsh->resultZ;
}

/***********************************************************************************************************************************
Shim for ssh_get_error_code
***********************************************************************************************************************************/
int
ssh_get_error_code(void *error)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_GET_ERROR_CODE, NULL, (HrnLibSsh *)error);

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_session_update_known_hosts
***********************************************************************************************************************************/
int
ssh_session_update_known_hosts(ssh_session session)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SESSION_UPDATE_KNOWN_HOSTS, NULL, (HrnLibSsh *)session);

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_new
***********************************************************************************************************************************/
sftp_session
sftp_new(ssh_session session)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SFTP_NEW, NULL, (HrnLibSsh *)session);

    return hrnLibSsh->resultNull ? NULL : (sftp_session)hrnLibSsh;
}

/***********************************************************************************************************************************
Shim for sftp_init
***********************************************************************************************************************************/
int
sftp_init(sftp_session sftpSession)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SFTP_INIT, NULL, (HrnLibSsh *)sftpSession);

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_free
***********************************************************************************************************************************/
void
sftp_free(sftp_session sftpsession)
{
    // Avoid compiler complaining of unused param - sftpsession can be null
    (void)sftpsession;
}

/***********************************************************************************************************************************
Shim for sftp_get_error
***********************************************************************************************************************************/
int
sftp_get_error(sftp_session sftpSession)
{
    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SFTP_GET_ERROR, NULL, (HrnLibSsh *)sftpSession);

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_get_poll_flags
***********************************************************************************************************************************/
int
ssh_get_poll_flags(ssh_session sshSession)
{
    return hrnLibSshScriptRun(HRNLIBSSH_GET_POLL_FLAGS, NULL, (HrnLibSsh *)sshSession)->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_userauth_try_publickey
***********************************************************************************************************************************/
int
ssh_userauth_try_publickey(ssh_session session, const char *username, ssh_key pubkey)
{
    // Avoid compiler complaining of unused param
    (void) pubkey;

    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_USERAUTH_TRY_PUBLICKEY,
            varLstAdd(
                varLstNew(), varNewStrZ(username)),
            (HrnLibSsh *)session);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_userauth_publickey
***********************************************************************************************************************************/
int
ssh_userauth_publickey(ssh_session session, const char *username, ssh_key privkey)
{
    // Avoid compiler complaining of unused param
    (void) privkey;

    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_USERAUTH_PUBLICKEY,
            varLstAdd(
                varLstNew(), varNewStrZ(username)),
            (HrnLibSsh *)session);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_pki_import_pubkey_file
***********************************************************************************************************************************/
int
ssh_pki_import_pubkey_file(const char *filename, ssh_key *key)
{
    (void)filename; // Avoid compiler complaining of unused param

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_PKI_IMPORT_PUBKEY_FILE, NULL, NULL);

    // Hack the key
    *(key) = (ssh_key)hrnLibSsh->resultZ;

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_pki_import_privkey_file
***********************************************************************************************************************************/
int
ssh_pki_import_privkey_file(const char *filename, const char *passphrase, ssh_auth_callback authCb, void *authCbData, ssh_key *key)
{
    (void)filename; // Avoid compiler complaining of unused param
    (void)passphrase;
    (void)authCb;
    (void)authCbData;

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_PKI_IMPORT_PRIVKEY_FILE, NULL, NULL);

    // Hack the key
    *(key) = (ssh_key)hrnLibSsh->resultZ;

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_stat
***********************************************************************************************************************************/
sftp_attributes
sftp_stat(sftp_session sftpSession, const char *path)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_STAT,
            varLstAdd(
                varLstNew(), varNewStrZ(path)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    sftp_attributes attrs = calloc(1, sizeof(struct sftp_attributes_struct));

    attrs->flags = 0;
    attrs->flags |= (uint32_t)hrnLibSsh->flags;

    attrs->permissions = 0;
    attrs->permissions |= (unsigned long)hrnLibSsh->attrPerms;

    attrs->mtime64 = (unsigned long)hrnLibSsh->mtime64;
    attrs->uid = (unsigned long)hrnLibSsh->uid;
    attrs->gid = (unsigned long)hrnLibSsh->gid;
    attrs->size = (unsigned long)hrnLibSsh->filesize;

    return hrnLibSsh->resultNull ? NULL : (sftp_attributes)attrs;
}

/***********************************************************************************************************************************
Shim for ssh_lstat
***********************************************************************************************************************************/
sftp_attributes
sftp_lstat(sftp_session sftpSession, const char *path)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_LSTAT,
            varLstAdd(
                varLstNew(), varNewStrZ(path)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    sftp_attributes attrs = calloc(1, sizeof(struct sftp_attributes_struct));

    attrs->flags = 0;
    attrs->flags |= (uint32_t)hrnLibSsh->flags;

    attrs->permissions = 0;
    attrs->permissions |= (unsigned long)hrnLibSsh->attrPerms;

    attrs->mtime64 = (unsigned long)hrnLibSsh->mtime64;
    attrs->uid = (unsigned long)hrnLibSsh->uid;
    attrs->gid = (unsigned long)hrnLibSsh->gid;
    attrs->size = (unsigned long)hrnLibSsh->filesize;

    if (hrnLibSsh->fileName != NULL)
        attrs->name = strdup(strZ(hrnLibSsh->fileName));

    return hrnLibSsh->resultNull ? NULL : (sftp_attributes)attrs;
}

/***********************************************************************************************************************************
Shim for sftp_readlink
***********************************************************************************************************************************/
char *
sftp_readlink(sftp_session sftpSession, const char *path)
{
    HrnLibSsh *hrnLibSsh = NULL;
    char *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_READLINK,
            varLstAdd(
                varLstNew(), varNewStrZ(path)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    if (hrnLibSsh->symlinkExTarget != NULL)
    {
        result = calloc(1, strSize(hrnLibSsh->symlinkExTarget) + 1);
        strncpy(result, strZ(hrnLibSsh->symlinkExTarget), strSize(hrnLibSsh->symlinkExTarget));
    }

    return hrnLibSsh->resultNull ? NULL : result;
}

/***********************************************************************************************************************************
Shim for ssh_finalize
***********************************************************************************************************************************/
int
ssh_finalize(void)
{
    return hrnLibSshScriptRun(HRNLIBSSH_FINALIZE, NULL, NULL)->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_opendir
***********************************************************************************************************************************/
sftp_dir
sftp_opendir(sftp_session sftpSession, const char *path)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_OPENDIR,
            varLstAdd(
                varLstNew(), varNewStrZ(path)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultNull ? NULL : (sftp_dir)hrnLibSsh;
}

/***********************************************************************************************************************************
Shim for sftp_readdir
***********************************************************************************************************************************/
sftp_attributes
sftp_readdir(sftp_session sftpSession, sftp_dir dir)
{
    // Avoid compiler complaining of unused param
    (void) dir;

    HrnLibSsh *hrnLibSsh = hrnLibSshScriptRun(HRNLIBSSH_SFTP_READDIR, NULL, (HrnLibSsh *)sftpSession);

    sftp_attributes attrs = calloc(1, sizeof(struct sftp_attributes_struct));

    attrs->flags = 0;
    attrs->flags |= (uint32_t)hrnLibSsh->flags;

    attrs->permissions = 0;
    attrs->permissions |= (unsigned long)hrnLibSsh->attrPerms;

    attrs->mtime64 = (unsigned long)hrnLibSsh->mtime64;
    attrs->uid = (unsigned long)hrnLibSsh->uid;
    attrs->gid = (unsigned long)hrnLibSsh->gid;
    attrs->size = (unsigned long)hrnLibSsh->filesize;

    if (hrnLibSsh->fileName != NULL)
        attrs->name = strdup(strZ(hrnLibSsh->fileName));

    return hrnLibSsh->resultNull ? NULL : (sftp_attributes)attrs;
}

/***********************************************************************************************************************************
Shim for sftp_closedir
***********************************************************************************************************************************/
int
sftp_closedir(sftp_dir dir)
{
    if (dir == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'sftp_closedir', expects dir to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }

    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_CLOSEDIR, NULL, (HrnLibSsh *)dir)->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_dir_eof
***********************************************************************************************************************************/
int
sftp_dir_eof(sftp_dir dir)
{
    if (dir == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'sftp_dir_eof', expects dir to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }

    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_DIR_EOF, NULL, (HrnLibSsh *)dir)->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_write
***********************************************************************************************************************************/
ssize_t
sftp_write(sftp_file file, const void *buf, size_t count)
{
    // Ignore random data at the end of the buffer
    ((char *)buf)[count] = '\0';

    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_WRITE,
            varLstAdd(
                varLstAdd(
                    varLstNew(), varNewStrZ((char*)buf)),
            varNewUInt64(count)),
            (HrnLibSsh *)file);
    }
    MEM_CONTEXT_TEMP_END();

    // Return number of bytes written
    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_open
***********************************************************************************************************************************/
sftp_file
sftp_open(sftp_session sftpSession, const char *file, int access, mode_t mode)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_OPEN,
            varLstAdd(
                varLstAdd(
                    varLstAdd(
                        varLstNew(), varNewStrZ(file)),
                    varNewInt(access)),
                varNewUInt64(mode)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultNull ? NULL : (sftp_file)hrnLibSsh;
}

/***********************************************************************************************************************************
Shim for sftp_mkdir
***********************************************************************************************************************************/
int
sftp_mkdir(sftp_session sftpSession, const char *path, mode_t mode)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_MKDIR,
            varLstAdd(
                varLstAdd(
                    varLstNew(), varNewStrZ(path)),
                varNewUInt64(mode)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_mkdir
***********************************************************************************************************************************/
int
sftp_close(sftp_file file)
{
    if (file == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'sftp_close', expects file to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }

    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_CLOSE, NULL, (HrnLibSsh *)file)->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_fsync
***********************************************************************************************************************************/
int
sftp_fsync(sftp_file file)
{
    if (file == NULL)
    {
        snprintf(
            hrnLibSshScriptError, sizeof(hrnLibSshScriptError),
            "libssh script function 'sftp_fsync', expects file to be not NULL");
        THROW(AssertError, hrnLibSshScriptError);
    }

    return hrnLibSshScriptRun(HRNLIBSSH_SFTP_FSYNC, NULL, (HrnLibSsh *)file)->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_rename
***********************************************************************************************************************************/
int
sftp_rename(sftp_session sftpSession, const char *source, const char *destination)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_RENAME,
            varLstAdd(
                varLstAdd(
                    varLstNew(), varNewStrZ(source)),
            varNewStrZ(destination)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_rmdir
***********************************************************************************************************************************/
int
sftp_rmdir(sftp_session sftpSession, const char *path)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_RMDIR,
            varLstAdd(
                varLstNew(), varNewStrZ(path)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_unlink
***********************************************************************************************************************************/
int
sftp_unlink(sftp_session sftpSession, const char *file)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_UNLINK,
            varLstAdd(
                varLstNew(), varNewStrZ(file)),
            (HrnLibSsh *)sftpSession);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_read
***********************************************************************************************************************************/
ssize_t
sftp_read(sftp_file file, void *buf, size_t count)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_READ,
            varLstAdd(
                varLstNew(), varNewUInt64(count)),
            (HrnLibSsh *)file);
    }
    MEM_CONTEXT_TEMP_END();

    // Copy the data to the buffer
    if (hrnLibSsh->readBuffer != NULL)
        strncpy(buf, strZ(hrnLibSsh->readBuffer), strSize(hrnLibSsh->readBuffer));

    // Return number of bytes read
    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for sftp_seek64
***********************************************************************************************************************************/
int
sftp_seek64(sftp_file file, uint64_t newOffset)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SFTP_SEEK64,
            varLstAdd(
                varLstNew(), varNewUInt64(newOffset)),
            (HrnLibSsh *)file);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}

/***********************************************************************************************************************************
Shim for ssh_session_set_disconnect_message
***********************************************************************************************************************************/
int
ssh_session_set_disconnect_message(ssh_session session, const char *message)
{
    HrnLibSsh *hrnLibSsh = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        hrnLibSsh = hrnLibSshScriptRun(
            HRNLIBSSH_SESSION_SET_DISCONNECT_MESSAGE,
            varLstAdd(
                varLstNew(), varNewStrZ(message)),
            (HrnLibSsh *)session);
    }
    MEM_CONTEXT_TEMP_END();

    return hrnLibSsh->resultInt;
}
#endif // HAVE_LIBSSH
