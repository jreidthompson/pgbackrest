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
int
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
int
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

        if (strcmp(dname, "trustad-fail") == 0)
        {
            result = 0;
        }
        else if (strcmp(dname, "trustad-pass") == 0)
        {
            result = 1;
        }
        else
        {
            result = -1;
            statep->res_h_errno = NO_DATA;
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
int
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

    // jrt !!! start here
    // Populate handle with dummy data for storageSftpNsMsgGetflag() to work


    FUNCTION_HARNESS_RETURN(INT, result);
}

/***********************************************************************************************************************************
Shim storageSftpNsMsgGetflag()
***********************************************************************************************************************************/
static int
storageSftpNsMsgGetflag(ns_msg handle, int ns_f_ad)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(VOID, handle);
        FUNCTION_HARNESS_PARAM(INT, ns_f_ad);
    FUNCTION_HARNESS_END();

    (void)handle;
    (void)ns_f_ad;

    int result;

    if (hrnSftpResolvStatic.localShimSftpResolv)
    {
        if (ns_f_ad == 1 )
            result = 1;
        else
            result = 0;
    }
    // Else call the normal function
    else
        result = storageSftpNsMsgGetflag_SHIMMED(handle, ns_f_ad);

    FUNCTION_HARNESS_RETURN(INT, result);
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
