/*
Source: IDLRESET.C - Attach to a server and do an Intruder Detection reset
By    : George Milliken
Date  : 02/15/94
Version 2.00


   This program attempts to attach and login to another server under a
   help desk ID.  Then perform a password reset on the Target User.

   The purpose is to allow help desk personnel to reset intruder lock
   outs without giving them a supervisor account the shell will login
   to.

   You must create a WFBIDLRESET object of type 5 (1280 decimal, 0x500)
   using the makeobj.exe

   Passwords to the WFBIDLRESET object can be changed by deleting the
   object using BINDEDIT and recreating it using makeobj with the new
   password.


*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dos.h>
#include <ctype.h>
#include <conio.h>
#include <time.h>
#include <assert.h>

#ifndef FAR
   #define FAR far
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAP_DRIVE 14       // drive N:

#include <nwalias.h>
#include <nwserver.h>
#include <nwcalls.h>
#include <nwbindry.h>
#include <nwcaldef.h>
#include <nwconnec.h>
#include <nwmisc.h>

#ifdef __cplusplus
}
#endif

static WORD connHandle;               // global for atexit()
static FILE *log_file;                // global log file pointer
static int bLoginFlag = 0;            // signals if logged in for atexit()
static int bAttachFlag = 0;           // signals if attached for atexit()

void done(void);                      // atexit() routine to drop LAN connections
void err_msg(char *msg);              // std error message printer
void GetLoginName(char* szLoginName); // whoami in C
int getsne(char *string);             // get string no echo (for passwords)


int main()
{
   WORD wNWError;                     // error return code
   char szTargetServerName[48];
   char szTargetUserId[48];
   char szTargetUserNewPassword[48];
   char szHelpDeskUserId[48];
   char szHelpDeskPassword[48];
   char szRealUserId[48];

   WORD connNumber;                   // connection number
   char objname[48];                  // misc vars
   WORD ObjectType;
   DWORD objID;
   BYTE logintime[7];
   BYTE bMoreFlag;
   int iDoneEditing = 0;              // signals to end data entry
   int ch = 'Y';                      // to recover keystrokes
   char szLogFilePath[256];
   char szLogFileName[256];
   int iFileTryCount = 0;


   struct {                           // LOGIN_CONTROL data struct
       BYTE bAccountExpirationDate[3];
       BYTE bAccountDisabledFlag;
       BYTE bPasswordExpirationDate[3];
       BYTE bGraceLogin;
       WORD wPasswordExpirationIntervals;
       BYTE bGraceLoginReset;
       BYTE bMinPwdLen;
       WORD wMaxConnections;
       BYTE bAllowedLoginBitMap[42];
       BYTE bLastLoginDateTime[6];
       BYTE bRestrictionFlags;
       BYTE bReserved;
       LONG lMaxDiskUsage;
       WORD wBadLoginCount;
       LONG lNextResetTime;
       BYTE bBadLoginAddress[12];
  } stLoginControl;


   // register an atexit() to ensure we disconnect from server
   atexit(done);

   // set control break checking off
   setcbrk(0);

   clrscr();

   printf("\nIntruder Detection Lockout Reset v0.90 (c) Copyright 1994 Wells Fargo Bank");


// clean up before printing to screen
   memset(szTargetServerName, 0x00, sizeof(szTargetServerName));
   memset(szTargetUserId, 0x00, sizeof(szTargetUserId));
   memset(szTargetUserNewPassword, 0x00, sizeof(szTargetUserNewPassword));
   memset(szHelpDeskUserId, 0x00, sizeof(szHelpDeskUserId));
   memset(szHelpDeskPassword, 0x00, sizeof(szHelpDeskPassword));

   while(!iDoneEditing) {

      gotoxy(10, 10);
      printf("Enter the Server Name         : ");

      gotoxy(10, 12);
      printf("Enter the Server Password     : ");

      gotoxy(10, 14);
      printf("Enter the User Name           : ");

      gotoxy(10, 16);
      printf("Enter the New User Password   : ");

      gotoxy(10, 19);
      printf("Is the above correct (Y/N) ?  : ");

      gotoxy(42, 10);
      clreol();
      gets(szTargetServerName);
      assert(strlen(szTargetServerName) < sizeof(szTargetServerName));

      gotoxy(42, 12);
      clreol();
      getsne(szHelpDeskPassword);
      assert(strlen(szHelpDeskPassword) < sizeof(szHelpDeskPassword));

      gotoxy(42, 14);
      clreol();
      gets(szTargetUserId);
      assert(strlen(szTargetUserId) < sizeof(szTargetUserId));

      gotoxy(42, 16);
      clreol();
      gets(szTargetUserNewPassword);
      assert(strlen(szTargetUserNewPassword) < sizeof(szTargetUserNewPassword));

      gotoxy(42, 19);
      clreol();
      ch = getch();

      iDoneEditing = (tolower(ch) == 'y' ? 1 : 0);

      if (!szTargetServerName[0] || !szHelpDeskPassword[0] || !szTargetUserId[0] || !szTargetUserNewPassword[0]) {
         err_msg("You must enter a value in ALL fields");
         iDoneEditing = 0;
      }

   }

   // upper case so Netware won't have a cow...
   strupr(szTargetServerName);
   strupr(szHelpDeskPassword);
   strupr(szTargetUserId);
   strupr(szTargetUserNewPassword);


   // hard coded values
   strcpy(szHelpDeskUserId, "WFBIDLRESET");    // the name of the Bindery Object
   sprintf(szLogFilePath, "%s/sys:system", szTargetServerName);
   strcpy(szLogFileName, "N:IDLRESET.LOG");
   ObjectType = 5;                             // and its type


   /* init the NW system */
   if (wNWError = NWCallsInit(NULL, NULL)){
      err_msg("NWCallsInit: failed");
      exit(1);
   }


   // get default connection ID --> szRealUserId
   GetLoginName(szRealUserId);


   /* recycle connection handle if there, else attach a new one */
   if (wNWError = NWGetConnectionHandle(szTargetServerName, 0, &connHandle, NULL)) {
      if (wNWError = NWAttachToFileServer(szTargetServerName, 0, &connHandle)) {
          err_msg("NWAttach failed");
          exit(1);
      }
   }

   bAttachFlag = 1;                       // so we don't loose orig connection
   // get logged in as the Help Desk super-object
   if (wNWError = NWLoginToFileServer(connHandle, szHelpDeskUserId, ObjectType, szHelpDeskPassword)) {
      err_msg("NWLogin failed!");
      exit(1);
   }
   else {
      bLoginFlag = 1;                       // so we don't loose orig connection
      if (wNWError = NWGetConnectionNumber(connHandle, &connNumber)) {
         err_msg("NWGetConnectionNumber failed");
         exit(1);
      }

      if (wNWError = NWGetConnectionInformation(connHandle, connNumber, (char FAR *)objname, (WORD FAR *)&ObjectType, (DWORD FAR *)&objID, (BYTE FAR *)logintime)) {
         err_msg("NWGetConnectionInformation failed");
         exit(1);
      }

      // map a temp dir handle to log file, upper for Netware
      strupr(szLogFilePath);
      if (wNWError = NWSetDriveBase(MAP_DRIVE, connHandle, 0, szLogFilePath, 0)) {
         err_msg("NWSetDriveBase failed");
         exit(1);
      }

      // check for contention on log, try 20 times

      log_file = NULL;
      iFileTryCount = 0;

      while (iFileTryCount < 20 && log_file == NULL) {
         log_file = fopen(szLogFileName, "a+");
         sleep(2);
         iFileTryCount++;
      }

      if (log_file == NULL) {
         err_msg("Log file open failed");
         exit(1);
      }

      // read login control property
      if (wNWError = NWReadPropertyValue(connHandle, szTargetUserId, OT_USER, "LOGIN_CONTROL", 1, &stLoginControl, &bMoreFlag, NULL)) {
         err_msg("NWReadPropertyValue failed LOGIN_CONTROL");
         exit(1);
      }

      // verify the lock status of user before resetting
      if (stLoginControl.bGraceLogin > 1 || stLoginControl.lNextResetTime == 0 || stLoginControl.wBadLoginCount == 0) {
         fprintf(log_file, "%02.2d/%02.2d/%02.2d - %02.2d:%02.2d:%02.2d %s %10.10s %10.10s %10.10s\n", (int)logintime[1], (int)logintime[2], (int)logintime[0], (int)logintime[3], (int)logintime[4], (int)logintime[5], "BAD RESET", szTargetServerName, szTargetUserId, szRealUserId);
         err_msg("This user does not need to be reset!");
      }
      else {

           // set lock out minutes to 0
           stLoginControl.lNextResetTime = 0;

           // set bad login attempts to 0
           stLoginControl.wBadLoginCount = 0;

           // set password expiration to 0
           memset(stLoginControl.bPasswordExpirationDate, 0x01, 3);

           if (wNWError = NWWritePropertyValue(connHandle, szTargetUserId, OT_USER, "LOGIN_CONTROL", 1, &stLoginControl, 0x00)) {
              err_msg("NWWritePropertyValue failed");
              exit(5);
           }

           // change the password on the target user

           if (wNWError = NWChangeObjectPassword(connHandle, szTargetUserId, OT_USER, "", szTargetUserNewPassword)) {
              err_msg("Password change error code");
              exit(1);
           }

           // log the event to file
           fprintf(log_file, "%02.2d/%02.2d/%02.2d - %02.2d:%02.2d:%02.2d %s %20.20s %48.48s %48.48s\n", (int)logintime[1], (int)logintime[2], (int)logintime[0], (int)logintime[3], (int)logintime[4], (int)logintime[5],"RESET PWD", szTargetServerName, szTargetUserId, szRealUserId);
           gotoxy(1,23);
           printf("Password successfully changed to [%s]\n", szTargetUserNewPassword);
           printf("User successfully reset! Press any key");
           getch();
           gotoxy(1,23);
           clreol();

      }
   }

   return(0);
}


void done(void)
{
   if (log_file) {
      fclose(log_file);
   }

   if (bLoginFlag) {
      NWLogoutFromFileServer(connHandle);
   }

   if (bAttachFlag) {
      NWDetachFromFileServer(connHandle);
   }

   printf("\nPress a key to exit! ");
   getch();

}

void err_msg(char *msg)
{
    gotoxy(1,23);
    printf("\a\a\a%s.  Press any key", msg);
    getch();
    gotoxy(1,23);
    clreol();
}

void GetLoginName(char* szLoginName)
{

   WORD wNWError;
   WORD tmpConnHandle;              // global for atexit()
   WORD tmpConnNumber;
   static char  objname[48];
   WORD  objtype;
   DWORD objID;
   BYTE  logintime[7];

   if (wNWError = NWGetDefaultConnectionID(&tmpConnHandle)) {
      err_msg("NWGetDefaultConnectionID failed");
      exit(1);
   }

   if (wNWError = NWGetConnectionNumber(tmpConnHandle, &tmpConnNumber)) {
      err_msg("NWGetConnectionNumber failed");
      exit(1);
   }

   if (wNWError = NWGetConnectionInformation(tmpConnHandle, tmpConnNumber, (char FAR *)objname, (WORD FAR *)&objtype, (DWORD FAR *)&objID, (BYTE FAR *)logintime)) {
      err_msg("NWGetConnectionInformation failed");
      exit(1);
   }

   strcpy(szLoginName, objname);    // return value
}

int getsne(char *string)
{
    int ch;
    char *tmpptr;

    tmpptr = string;

    while ((ch = getch()) != '\r') {

      *tmpptr = ch;

      if (ch != '\b') {
         tmpptr++;
      }

    }

    tmpptr = 0x00;
    return(strlen(string));
}