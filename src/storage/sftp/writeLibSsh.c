/***********************************************************************************************************************************
SFTP Storage File Write
***********************************************************************************************************************************/
#include "build.auto.h"

#ifdef HAVE_LIBSSH

#include "common/debug.h"
#include "common/log.h"
#include "common/user.h"
#include "storage/sftp/writeLibSsh.h"
#include "storage/write.intern.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct StorageWriteSftp
{
    StorageWriteInterface interface;                                // Interface
    StorageSftp *storage;                                           // Storage that created this object

    const String *nameTmp;                                          // Temporary filename utilized for atomic ops
    const String *path;                                             // Utilized for path operations
    ssh_session session;                                            // LibSsh session
    sftp_session sftpSession;                                       // LibSsh session sftp session
    sftp_file sftpHandle;                                           // LibSsh session sftp handle
} StorageWriteSftp;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
#define FUNCTION_LOG_STORAGE_WRITE_SFTP_TYPE                                                                                       \
    StorageWriteSftp *
#define FUNCTION_LOG_STORAGE_WRITE_SFTP_FORMAT(value, buffer, bufferSize)                                                          \
    objNameToLog(value, "StorageWriteSftp", buffer, bufferSize)

/***********************************************************************************************************************************
Open the file
***********************************************************************************************************************************/
static void
storageWriteSftpOpen(THIS_VOID)
{
    THIS(StorageWriteSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_WRITE_SFTP, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(this->sftpSession != NULL);

    // jrt const unsigned long int flags = LIBSSH2_FXF_CREAT | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC;
    const int access_type =  O_WRONLY | O_CREAT | O_TRUNC;

    this->sftpHandle = sftp_open(this->sftpSession, strZ(this->nameTmp), access_type, this->interface.modeFile);

    // Attempt to create the path if it is missing
    if (this->sftpHandle == NULL && sftp_get_error(this->sftpSession) == SSH_FX_NO_SUCH_FILE)
    {
        // Create the path
        storageInterfacePathCreateP(this->storage, this->path, false, false, this->interface.modePath);

        // Open file again
        this->sftpHandle = sftp_open(this->sftpSession, strZ(this->nameTmp), access_type, this->interface.modeFile);
    }

    // Handle error
    if (this->sftpHandle == NULL)
    {
        const int sftpErr = sftp_get_error(this->sftpSession);

        if (sftpErr == SSH_FX_NO_SUCH_FILE)
        {
            THROW_FMT(
                FileMissingError,
                STORAGE_ERROR_WRITE_MISSING ": %s [%d] libssh sftp error [%d]", strZ(this->interface.name),
                ssh_get_error(this->session), ssh_get_error_code(this->session), sftpErr);
        }
        else
        {
            THROW_FMT(
                FileOpenError,
                STORAGE_ERROR_WRITE_OPEN ": %s [%d] libssh sftp error [%d]", strZ(this->nameTmp), ssh_get_error(this->session),
                ssh_get_error_code(this->session), sftpErr);
        }
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Write to the file
***********************************************************************************************************************************/
static void
storageWriteSftp(THIS_VOID, const Buffer *const buffer)
{
    THIS(StorageWriteSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_WRITE_SFTP, this);
        FUNCTION_LOG_PARAM(BUFFER, buffer);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(buffer != NULL);
    ASSERT(this->sftpHandle != NULL);

    ssize_t rc;
    size_t remains = bufUsed(buffer);                               // Amount left to write
    size_t offset = 0;                                              // Offset into the buffer

    // Write the data
    do
    {
        rc = sftp_write(this->sftpHandle, (const char *)bufPtrConst(buffer) + offset, remains);

        // Break on error. Error will be thrown below the loop.
        if (rc < 0)
            break;

        // Offset for next write start point
        offset += (size_t)rc;

        // Update amount left to write
        remains -= (size_t)rc;
    }
    while (remains);

    if (rc < 0)
    {
        THROW_FMT(
            FileWriteError,
            "unable to write '%s': %s [%d] libssh sftp error [%d]", strZ(this->nameTmp), ssh_get_error(this->session),
            ssh_get_error_code(this->session), sftp_get_error(this->sftpSession));
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Unlink already existing file
***********************************************************************************************************************************/
static void
storageWriteSftpUnlinkExisting(THIS_VOID)
{
    THIS(StorageWriteSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_WRITE_SFTP, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    if (sftp_unlink(this->sftpSession, strZ(this->interface.name)) < 0)
    {
        THROW_FMT(
            FileRemoveError, "unable to remove existing '%s': %s libssh sftp error [%d]", strZ(this->interface.name),
            ssh_get_error(this->session), sftp_get_error(this->sftpSession));
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Rename a file
***********************************************************************************************************************************/
static void
storageWriteSftpRename(THIS_VOID)
{
    THIS(StorageWriteSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_WRITE_SFTP, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    if (sftp_rename(this->sftpSession, strZ(this->nameTmp), strZ(this->interface.name)) < 0)
    {
        THROW_FMT(
            FileRemoveError, "unable to move '%s' to '%s': %s libssh sftp error [%d]", strZ(this->nameTmp),
            strZ(this->interface.name), ssh_get_error(this->session), sftp_get_error(this->sftpSession));
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Close the file
***********************************************************************************************************************************/
static void
storageWriteSftpClose(THIS_VOID)
{
    THIS(StorageWriteSftp);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_WRITE_SFTP, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    // Close if the file has not already been closed
    if (this->sftpHandle != NULL)
    {
        // Sync the file
        if (this->interface.syncFile)
            if (sftp_fsync(this->sftpHandle) < 0)
            {
                THROW_FMT(
                    FileSyncError,
                    STORAGE_ERROR_WRITE_SYNC ": %s libssh sftp error [%d]", strZ(this->nameTmp), ssh_get_error(this->session),
                    sftp_get_error(this->sftpSession));
            }

        // Close the file
        if (sftp_close(this->sftpHandle) < 0)
        {
            THROW_FMT(
                FileCloseError,
                STORAGE_ERROR_WRITE_CLOSE ": %s libssh sftp error [%d]", strZ(this->nameTmp), ssh_get_error(this->session),
                sftp_get_error(this->sftpSession));
        }

        // Rename from temp file
        if (this->interface.atomic)
        {
            // Rename from temp file
            if (sftp_rename(this->sftpSession, strZ(this->nameTmp), strZ(this->interface.name)) < 0)
            {
                int sftpErr = sftp_get_error(this->sftpSession);

                // Some/most sftp servers will not rename over an existing file, in testing this returned SSH_FX_FAILURE
                if (sftpErr == SSH_FX_FAILURE || sftpErr == SSH_FX_FILE_ALREADY_EXISTS)
                {
                    // Remove the existing file and retry the rename
                    storageWriteSftpUnlinkExisting(this);
                    storageWriteSftpRename(this);
                }
                else
                {
                    THROW_FMT(
                        FileCloseError,
                        "unable to move '%s' to '%s': %s [%d] libssh sftp error [%d]", strZ(this->nameTmp),
                        strZ(this->interface.name), ssh_get_error(this->session), ssh_get_error_code(this->session), sftpErr);
                }
            }
        }
    }

    FUNCTION_LOG_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN StorageWrite *
storageWriteSftpNew(
    StorageSftp *const storage, const String *const name, ssh_session *const session, sftp_session *const sftpSession,
    sftp_file *sftpHandle, const mode_t modeFile, const mode_t modePath, const String *const user, const String *const group,
    const time_t timeModified, const bool createPath, const bool syncFile, const bool syncPath, const bool atomic,
    const bool truncate)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STORAGE_SFTP, storage);
        FUNCTION_LOG_PARAM(STRING, name);
        FUNCTION_LOG_PARAM_P(VOID, session);
        FUNCTION_LOG_PARAM_P(VOID, sftpSession);
        // jrt is this right for file handle?
        FUNCTION_LOG_PARAM_P(VOID, sftpHandle);
        FUNCTION_LOG_PARAM(MODE, modeFile);
        FUNCTION_LOG_PARAM(MODE, modePath);
        FUNCTION_LOG_PARAM(STRING, user);
        FUNCTION_LOG_PARAM(STRING, group);
        FUNCTION_LOG_PARAM(TIME, timeModified);
        FUNCTION_LOG_PARAM(BOOL, createPath);
        FUNCTION_LOG_PARAM(BOOL, syncFile);
        FUNCTION_LOG_PARAM(BOOL, syncPath);
        FUNCTION_LOG_PARAM(BOOL, atomic);
        FUNCTION_LOG_PARAM(BOOL, truncate);
    FUNCTION_LOG_END();

    ASSERT(storage != NULL);
    ASSERT(name != NULL);
    ASSERT(modeFile != 0);
    ASSERT(modePath != 0);

   OBJ_NEW_BEGIN(StorageWriteSftp, .childQty = MEM_CONTEXT_QTY_MAX)
   {
       *this = (StorageWriteSftp)
       {
           .storage = storage,
           .path = strPath(name),
           .session = *session,
           .sftpSession = *sftpSession,
           .sftpHandle = *sftpHandle,

           .interface = (StorageWriteInterface)
           {
               .type = STORAGE_SFTP_TYPE,
               .name = strDup(name),
               .atomic = atomic,
               .createPath = createPath,
               .group = strDup(group),
               .modeFile = modeFile,
               .modePath = modePath,
               .syncFile = syncFile,
               .syncPath = syncPath,
               .truncate = truncate,
               .user = strDup(user),
               .timeModified = timeModified,

               .ioInterface = (IoWriteInterface)
               {
                   .close = storageWriteSftpClose,
                   .open = storageWriteSftpOpen,
                   .write = storageWriteSftp,
               },
           },
       };

       // Create temp file name
       this->nameTmp = atomic ? strNewFmt("%s." STORAGE_FILE_TEMP_EXT, strZ(name)) : this->interface.name;
   }
   OBJ_NEW_END();

   FUNCTION_LOG_RETURN(STORAGE_WRITE, storageWriteNew(this, &this->interface));
}
#else
#include <stdbool.h>

bool
satisfyCodeCoverageWhenLibsshIsNotLinkedWrite(void)
{
    return true;
}
#endif // HAVE_LIBSSH
