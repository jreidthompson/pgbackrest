#ifdef HAVE_LIBSSH
/***********************************************************************************************************************************
SFTP Storage File Write
***********************************************************************************************************************************/
#ifndef STORAGE_SFTP_LIBSSHWRITE_H
#define STORAGE_SFTP_LIBSSHWRITE_H

#include <fcntl.h>
#include "common/io/session.h"
#include "storage/sftp/storage.h"
#include "storage/sftp/storage.intern.h"

/***********************************************************************************************************************************
Constructors
***********************************************************************************************************************************/
FN_EXTERN StorageWrite *storageWriteSftpNew(
    StorageSftp *storage, const String *name, ssh_session *session, sftp_session *sftpSession, sftp_file *sftpHandle,
    mode_t modeFile, mode_t modePath, const String *user, const String *group, time_t timeModified, bool createPath, bool syncFile,
    bool syncPath, bool atomic, bool truncate);

#endif
#endif // HAVE_LIBSSH
