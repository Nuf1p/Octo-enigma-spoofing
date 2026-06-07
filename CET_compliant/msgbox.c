#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA(HWND hWnd, LPCSTR lpText,
                                                LPCSTR lpCaption, UINT uType);
void msgbox() ;

void go(char *args, unsigned long alen) 
{
      msgbox() ;
}

void msgbox() 
{
      LPCSTR text    = "BoF Executed";
      LPCSTR caption = "BOF";
      USER32$MessageBoxA(NULL, text, caption, MB_OK | MB_ICONINFORMATION);
      BeaconPrintf(0, "[+] MessageBoxA returned\n");
}
