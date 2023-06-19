#include <string>
#include <vector>
#include <fstream>

#include <windows.h>

#include <msi.h>
#include <msiquery.h>

using namespace std;

extern "C" UINT __stdcall ValidateDependencies(MSIHANDLE msi_handle)
{
    //PMSIHANDLE hRecord = MsiCreateRecord(0);
    //MsiRecordSetString(hRecord, 0, TEXT("Enter the text for the error!"));
    //MsiProcessMessage(msi_handle, INSTALLMESSAGE(INSTALLMESSAGE_ERROR + MB_OK), hRecord);
    //return ERROR_INSTALL_USEREXIT;
    return ERROR_SUCCESS;
}