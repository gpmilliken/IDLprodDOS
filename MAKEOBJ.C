/*
Source: makeobj.C - Attach to a server and create a super object
By    : George Milliken
Date  : 02/10/94
Version 1.00
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <time.h>

#ifndef FAR
   #define FAR far
#endif

#ifdef __cplusplus
extern "C" {
#endif

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


main(int argc, char *argv[])
{
   WORD wNWError;                       // holds return codes
   char szTargetServerName[256];        // server to create the object on
   char szTargetObjectPassword[256];    // password for the new object
   char szTargetObjectName[256];        // target object name
   char szHelpDeskUserId[256];          // authorized user name
   char szHelpDeskPassword[256];        // authorized user's password
   NWOBJ_TYPE oTargetObjectType;        // object type code (OT_xxxx)

   WORD  connNumber;                    // connection number
   WORD  connHandle;                    // connection handle

   BYTE  logintime[7];                  // time the login occurred (for log)
   char  objname[48];                   // used for get connection verification call
   NWOBJ_TYPE objtype;                  // ditto
   DWORD objID;                         // ditto

   struct {                             // used to make the object
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


   printf("\nMake Object Utility 1.00\n\n");


   /* check parm count */
   if (argc != 7) {
      printf("Usage:   makeobj TargetServer NewObject NewObjectPwd NewObjectType YourID YourPwd\n");
      exit(1);
   }


   // recover command line parms

   strcpy(szTargetServerName, strupr(argv[1]));
   strcpy(szTargetObjectName, strupr(argv[2]));
   strcpy(szTargetObjectPassword, strupr(argv[3]));
   oTargetObjectType = atoi(argv[4]);
   strcpy(szHelpDeskUserId, strupr(argv[5]));
   strcpy(szHelpDeskPassword, strupr(argv[6]));


   /* init the NW system */
   if (wNWError = NWCallsInit(NULL, NULL)){
      printf("NWCallsInit: failed %04x\n",wNWError);
      exit(1);
   }

   // get logged in, use existing connection if available
   if (wNWError = NWGetConnectionHandle(szTargetServerName, 0, &connHandle, NULL)) {
      if (wNWError = NWAttachToFileServer(szTargetServerName, 0, &connHandle)) {
          printf("NWAttach failed %04x\n",wNWError);
          exit(1);
      }
   }


   // get logged in as the Help Desk super-object, no password for testing

   if (wNWError = NWLoginToFileServer(connHandle, szHelpDeskUserId, OT_USER, szHelpDeskPassword)) {
      printf("NWLogin failed %04x\n", wNWError);
      exit(4);
   }

   printf("Connection Handle %d, Connection %d\n",connHandle, connNumber);


   // create the bindery object

   printf("Making the bindery object now...\n");

   // should see if it's there and just update it if it exists...

   // should be loggin all this stuff to disk


   if (wNWError = NWCreateObject(connHandle, szTargetObjectName, oTargetObjectType, BF_STATIC, BS_ANY_READ | BS_SUPER_WRITE)) {
      printf("NWCreateObject failed %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(2);
   }

   if (wNWError = NWChangeObjectPassword(connHandle, szTargetObjectName, oTargetObjectType, "", szTargetObjectPassword)) {
      printf("NWChangeObjectPassword failed %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(3);
   }

   if (wNWError = NWCreateProperty(connHandle, szTargetObjectName, oTargetObjectType, "LOGIN_CONTROL", BF_STATIC | BF_ITEM, BS_ANY_READ | BS_SUPER_WRITE)) {
      printf("NWCreateProperty failed %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(4);
   }

   memset(&stLoginControl, 0x00, sizeof(stLoginControl));
   memset(stLoginControl.bAllowedLoginBitMap, 0xFF, 42);

   if (wNWError = NWWritePropertyValue(connHandle, szTargetObjectName, oTargetObjectType, "LOGIN_CONTROL", 1, &stLoginControl, 0x00)) {
      printf("NWWritePropertyValue failed %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(5);
   }


   // create SECURITY_EQUALS
   if (wNWError = NWCreateProperty(connHandle, szTargetObjectName, oTargetObjectType, "SECURITY_EQUALS", BF_STATIC | BF_SET, BS_ANY_READ | BS_SUPER_WRITE)) {
      printf("NWCreateProperty failed %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(6);
   }

   // add to SECUIRTY_EQUALS SET
   if (wNWError = NWAddObjectToSet(connHandle, szTargetObjectName, oTargetObjectType, "SECURITY_EQUALS", "SUPERVISOR", OT_USER)) {
      printf("NWAddObjectToSet failed create supervisor equiv %04x\tobject type %04x\n", wNWError, oTargetObjectType);
      exit(7);
   }

   printf("\n!!!   DONE   !!!\n");

   return(0);
}

