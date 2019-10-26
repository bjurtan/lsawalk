// lsawalk
// Copyright Björn Spåra 2006
// Inspired by sid2user/user2sid by Evgenii Rudny
// http://evgenii.rudnyi.ru/soft/sid/
// ..and an article by Chris Gates
// http://www.windowsecurity.com/whitepaper/Windows-Enumeration-USER2SID-SID2USER.html
// No warranties yada yada..

#include <iostream>
#include <windows.h>

#define MAX_UNUSED_SIDS     600     // This value seems to work at my site.
                                    // The lower this can be the faster lsawalk
                                    // will know when to stop walking.

#define RID_START           500     // RID where the walking begins.
                                    // 500 is the Administrator account and
                                    // makes for a good start.

#define RID_STOP            65535   // The last possible RID to be walked.
                                    // 65535 is the logical maximum allowed.

// Simple error handling
void ExitWithError(LPTSTR lpszFunction)
{

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;

    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0,
        NULL );

    lpDisplayBuf = (LPVOID)LocalAlloc(
        LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf)+lstrlen((LPCTSTR)lpszFunction)+40)*sizeof(TCHAR));

    wsprintf((LPTSTR)lpDisplayBuf,
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);

    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("lsawalk error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw);
}

// _main entrypoint function
int main(int argc, char **argv)
{
    if( argc < 2 || argc > 2 ) // Wrong number of params
    {
        std::cout << "lsawalk - bjorn.spara@gmail.com" << std::endl;
        std::cout << "Inspired by user2sid/sid2user by Evgenii Rudny" << std::endl;
        std::cout << "and Windows Enumeration: USER2SID & SID2USER article by Chris Gates" << std::endl << std::endl;
        std::cout << "Usage: lsawalk [NAME/IP]" << std::endl;

        // Exit
        return 0;
    }
    else // Correct number of params
    {
        LPCTSTR lpSystemName;
        if ( argv[1][0] == '\\' && argv[1][1] == '\\' ) // if double baskslash
        {
            lpSystemName = argv[1] + 2; // adjust string to exclude baskslash
        }
        lpSystemName = argv[1];
        LPCTSTR Domain_Admins = "Domain Admins"; // Built in global group. Non-renameable!
        UCHAR sid_buffer[1024]; PSID Sid = sid_buffer;
        DWORD sid_length = sizeof(sid_buffer); LPDWORD cbSid = &sid_length;
        TCHAR sid_domain[1024]; LPTSTR sid_ReferencedDomainName = sid_domain;
        DWORD sid_domain_length = sizeof(sid_domain); LPDWORD cbReferencedDomainName = &sid_domain_length;
        UCHAR sid_enum_type[4]; PSID_NAME_USE sidUse  = (PSID_NAME_USE) sid_enum_type;

        // Call Win32 API function LookupAccountName and check for errors
        if (!LookupAccountName(
            lpSystemName,
            Domain_Admins,
            Sid,
            cbSid,
            sid_ReferencedDomainName,
            cbReferencedDomainName,
            sidUse))
        {
            // TODO: Not all errors are critical. IF the SID looped does
            // not have a corresponding account, an error is producers. This
            // should just be ignired and the loop should continue.

            // There was an error. Tell the user..
            ExitWithError("LookupAccountName");
        }
        else
        {
            // Got Sid, check if it is valid
            if (!IsValidSid(Sid))
            {
                ExitWithError("IsValidSid");
            }

            TCHAR account_name_buffer[1024]; LPTSTR lpName = account_name_buffer;
            DWORD account_name_length; LPDWORD cchName = &account_name_length; // Must be reset for each loop
            TCHAR domain_name_buffer[1024]; LPTSTR name_ReferencedDomainName = domain_name_buffer;
            DWORD domain_name_length; LPDWORD cchReferencedDomainName = &domain_name_length; // Must be reset for each loop
            // UCHAR name_enum_type[4]; PSID_NAME_USE nameUse  = (PSID_NAME_USE) name_enum_type;
            SID_NAME_USE nameUse;

            // This little counter keeps track of how many consecutive sid's
            // do not translate to an account. This is later checked in the loop
            // and if the value passes MAX_UNUSED_SIDS, the loop breaks.
            int numUnusedSids = 0;
            int n = *GetSidSubAuthorityCount(Sid); // How many RID's in th SID?
            DWORD * Rid = GetSidSubAuthority(Sid, n-1); // Single out the last RID
            DWORD LastError; // Temp storage for error code comparison

            std::cout << "Account_Name,Sid_Type,Host_Name,Domain_Name" << std::endl;

            // Loop through all possible RID's
            for (int i=RID_START; i<RID_STOP; i++)
            {

                if (numUnusedSids > MAX_UNUSED_SIDS) break;
                *Rid = i;
                account_name_length = sizeof(account_name_buffer); // Must be reset..
                domain_name_length = sizeof(domain_name_buffer); // each loop because..

                if (!LookupAccountSid(
                    lpSystemName,
                    Sid,
                    lpName,
                    cchName, // this..
                    name_ReferencedDomainName,
                    cchReferencedDomainName, // and this, are used for input AND output!
                    &nameUse))
                {
                    // LookupAccountSid indicated an error
                    LastError = GetLastError(); // Get error code
                    if( LastError != 1332)  // ..and filter out all
                    {                       // .."no such sid" errors.
                        ExitWithError("LookupAccountSid");      // Other errors.
                    } // ..and continue the loop quietly
                    else
                    {
                        numUnusedSids++;
                    }
                }
                else
                { // No error, print out account name
                    std::cout << lpName << ",";
                    switch (nameUse)
                    {
                        case 1:
                            std::cout << "USER,";
                            break;
                        case 2:
                            std::cout << "GROUP,";
                            break;
                        case 3:
                            std::cout << "DOMAIN,";
                            break;
                        case 4:
                            std::cout << "ALIAS,";
                            break;
                        case 5:
                            std::cout << "WELL_KNOWN_GROUP,";
                            break;
                        case 6:
                            std::cout << "DELETED_ACCOUNT,";
                            break;
                        case 7:
                            std::cout << "INVALID,";
                            break;
                        case 8:
                            std::cout << "UNKNOWN,";
                            break;
                        case 9:
                            std::cout << "COMUPTER,";
                            break;
                        default:
                            std::cout << "OTHER,";
                            break;
                    }
                    std::cout << lpSystemName << ",";
                    std::cout << name_ReferencedDomainName << std::endl;
                    numUnusedSids = 0; // reset counter
                }
            }
            MessageBox(NULL, TEXT("lsawalk finnished successfully!"), TEXT("lsawalk"), MB_OK);
        }
        return 0; // All went well..
    }
    return 0; // Never reached..
}

