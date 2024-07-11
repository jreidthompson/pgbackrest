#ifdef HAVE_LIBSSH
/***********************************************************************************************************************************
SFTP Storage Read
***********************************************************************************************************************************/
#ifndef STORAGE_SFTP_LIBSSHREAD_H
#define STORAGE_SFTP_LIBSSHREAD_H

#include <fcntl.h>
#include "storage/read.h"
#include "storage/sftp/storage.intern.h"

/***********************************************************************************************************************************
Constructors
***********************************************************************************************************************************/
FN_EXTERN StorageRead *storageReadSftpNew(
    StorageSftp *storage, const String *name, bool ignoreMissing, ssh_session *session, sftp_session *sftpSession,
    sftp_file *sftpHandle, uint64_t offset, const Variant *limit);

#endif
#endif // HAVE_LIBSSH
