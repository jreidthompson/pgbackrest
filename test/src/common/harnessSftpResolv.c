/***********************************************************************************************************************************
Harness for SFTP libresolv Testing
***********************************************************************************************************************************/
#include "build.auto.h"

#include "common/harnessConfig.h"
#include "common/harnessDebug.h"
#include "common/harnessSftpResolv.h"

#include <arpa/nameser.h>
#ifndef __USE_MISC
#define __USE_MISC                                                  1
#endif
#include <netdb.h>

/***********************************************************************************************************************************
Include shimmed C modules
***********************************************************************************************************************************/
{[SHIM_MODULE]}

/***********************************************************************************************************************************
Shim install state
***********************************************************************************************************************************/
static struct
{
    bool localShimSftpResolv;                                       // Is the shim installed?
} hrnSftpResolvStatic;

/***********************************************************************************************************************************
Shim storageSftpResNinit()
***********************************************************************************************************************************/
static int
storageSftpResNinit(res_state statep)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM_P(VOID, statep);
    FUNCTION_HARNESS_END();

    int result;

    if (hrnSftpResolvStatic.localShimSftpResolv)
    {
        // Use the RES_IGNTC option indicate when to return a failure
        if ((my_res_state.options & RES_IGNTC) == RES_IGNTC)
            result = -1;
        else
            result = 0;
    }
    // Else call the normal function
    else
        result = storageSftpResNinit_SHIMMED(statep);

    FUNCTION_HARNESS_RETURN(INT, result);
}

/***********************************************************************************************************************************
Shim storageSftpResNquery()
***********************************************************************************************************************************/
static int
storageSftpResNquery(res_state statep, const char *dname, int class, int type, unsigned char *answer, int anslen)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM_P(VOID, statep);
        FUNCTION_HARNESS_PARAM(STRINGZ, dname);
        FUNCTION_HARNESS_PARAM(INT, class);
        FUNCTION_HARNESS_PARAM(INT, type);
        FUNCTION_HARNESS_PARAM(UCHARDATA, answer);
        FUNCTION_HARNESS_PARAM(INT, anslen);
    FUNCTION_HARNESS_END();

    int result;

    (void)statep;
    (void)dname;
    (void)class;
    (void)type;
    (void)answer;
    (void)anslen;

    if (hrnSftpResolvStatic.localShimSftpResolv)
    {
        HEADER *header = (HEADER *)answer;

        if (strcmp(dname, "trustad-fail") == 0)
        {
            result = 0;
            header->ad = 0;
        }
        else if (strcmp(dname, "trustad-pass") == 0 || strcmp(dname, "localhost") == 0)
        {
            result = 1;
            header->ad = 1;
        }
        else
        {
            result = -1;
            statep->res_h_errno = NO_DATA;
            header->ad = 0;
        }
    }
    // Else call the normal function
    else
        result = storageSftpResNquery_SHIMMED(statep, dname, class, type, answer, anslen);

    FUNCTION_HARNESS_RETURN(INT, result);
}

/***********************************************************************************************************************************
Shim storageSftpNsInitparse()
***********************************************************************************************************************************/
static int
storageSftpNsInitparse(const unsigned char *answer, int len, ns_msg *handle)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(UCHARDATA, answer);
        FUNCTION_HARNESS_PARAM(INT, len);
        FUNCTION_HARNESS_PARAM_P(VOID, handle);
    FUNCTION_HARNESS_END();

    int result;

    if (hrnSftpResolvStatic.localShimSftpResolv)
    {
        switch (len)
        {
            case 0:
                result = 0;
                break;

            case 1:
                result = 1;
                break;

            default:
                result = -1;
                break;
        }
    }
    else
        result = storageSftpNsInitparse_SHIMMED(answer, len, handle);

    FUNCTION_HARNESS_RETURN(INT, result);
}

/***********************************************************************************************************************************
Shim storageSftpVerifyFingerprint()
***********************************************************************************************************************************/
static void
storageSftpVerifyFingerprint(LIBSSH2_SESSION *const session, ns_msg handle)
{
    if (session == NULL)
        THROW(AssertError, "storageSftpVerifyFingerprint expects 'session' to be not null");

    if (hrnSftpResolvStatic.localShimSftpResolv)
    {
    }
    else
        storageSftpVerifyFingerprint_SHIMMED(session, handle);
}

/**********************************************************************************************************************************/
void
hrnSftpResolvShimInstall(void)
{
    FUNCTION_HARNESS_VOID();

    hrnSftpResolvStatic.localShimSftpResolv = true;

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
hrnSftpResolvShimUninstall(void)
{
    FUNCTION_HARNESS_VOID();

    hrnSftpResolvStatic.localShimSftpResolv = false;

    FUNCTION_HARNESS_RETURN_VOID();
}
