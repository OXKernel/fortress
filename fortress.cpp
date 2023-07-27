/*
 * Copyright (C) 2023. Roger Doss. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "GLOBALS.h"
#include "password.h"

/////global constants///////////////////////////////////////////////////////////
const uint16 ROUNDS      =    16;
const uint16 NOPERATIONS =     8; // 8 operations
const bool   ENCRYPT     =  true;
const bool   DECRYPT     = false;
union sblock {                    // break up 32bit subblock
      uint32 blck;                // into two 16bit blocks,b[0],b[1]
      uint16 b[2];
};

/////macros/////////////////////////////////////////////////////////////////////
#define DEBUG() { \
        printf("%d\n",__LINE__); \
        } \

#define DUMPKEY(k) { \
        for(int i=0;i<NOPERATIONS;i++) \
             printf("%d\t",k[i]); \
        printf("\n"); \
        } \

/////function prototypes////////////////////////////////////////////////////////

/////fortress cipher////
void   Fortress(const char *pass, const char *file, uint32 *data,size_t size,bool mode);
void   fortress(uint32 *data, size_t size, uint16 *k);
uint32 f(uint32 R, uint16 *key);


/////key management/////
uint16 *KeyCreate(void);
void   KeySchedule(uint16 *k);
void   KeyDestroy(uint16  *k);
void   KeyInverse(uint16  *ek,uint16  *dk);
void   KeySave   (const char *pass, const char *file, uint16   *k);
void   KeyRestore(const char *pass, const char *file, uint16   *k);
void   cipher_key(const char *pass, bool mode, uint16 *k);

/////math//////////////
uint16 add(sint32 a, sint32 b);
uint16 addinv(uint16 x);
uint16 multiply(sint32 a, sint32 b);

/////main///////////////////////////////////////////////////////////////////////
int main(int argc,char **argv)
{
   FILE    *fp;
   char  *data;
   size_t size;
   bool   mode;
   char  *pass;

   if(argc != 3) {
         fprintf(stderr,"syntax:: fort filename -e|-d\n");
         exit(-1);
   }

   if(strcmp(argv[2],"-e")==0)      mode=ENCRYPT;
   else if(strcmp(argv[2],"-d")==0) mode=DECRYPT;
   else {
         fprintf(stderr,"\t %s ERROR INVALID MODE %s\n",argv[0],argv[2]);
         fprintf(stderr,"\t syntax %s filename [-e|-d]\n",argv[0]);
         exit(-2);
   }

   pass = get_password("enter password:");
   char *retyped_pass = get_password("\nre-enter password:");
   if(strcmp(pass, retyped_pass) != 0) {
    fprintf(stderr, "\t %s ERROR DIFFERING PASSWORDS RECEIVED \n", argv[0]);
    exit(-3);
   }

   fp = fopen(argv[1],"rb");
   if(fp == NULL) {
         fprintf(stderr,"\t %s ERROR OPENING FILE FOR READ %s\n",argv[0],argv[1]);
         exit(-4);
   }

   fseek(fp,0,SEEK_END);
   size=ftell(fp);
   rewind(fp);
   size_t orig_size = size;

   while(true) {
       /* pad if needed */
       if(((size / 4) % 4) != 0)       /* use this to calculate the size of the pad */
              size++;                  /* valid if size of the file is in bytes     */
       else break;
   }
   data = new char[size * 2];
   memset(data,0x0,size);
   fread(data,size,1,fp);
   fclose(fp);

   /* tell user we are OK */
   if(mode==ENCRYPT)
         fprintf(stdout,"%s ENCRYPTING... \nFILE (%s) SIZE (%ld) bytes\n",argv[0],argv[1],size);
   else
         fprintf(stdout,"%s DECRYPTING... \nFILE (%s) SIZE (%ld) bytes\n",argv[0],argv[1],size);

   Fortress(pass, argv[1], (uint32 *)data,size/4,mode);
   fp=fopen(argv[1],"wb");
   if(fp == NULL) {
         delete[] data;
         fprintf(stderr,"\t %s ERROR OPENING FILE FOR WRITE %s\n",argv[0],argv[1]);
         exit(-5);
   }
   if(mode == ENCRYPT) {
     fwrite(data,size,1,fp);
   } else {
     size_t offset = 0, i = size - 1;
     for(; i >= 0; --i) {
        if(data[i] == 0x0) { offset++; continue; }
        else break;
     }
     printf("decrypt offset %ld\n",offset);
     fwrite(data,size-offset,1,fp);
   }
   delete[] data;
   delete[] pass;
   fclose(fp);
   return 0;

}/* main() */

#if 0
main()
{
   uint32 data[] = {0x23,0x34,0x88,0x17};
   uint32 data_c[4];

   uint16 key[]  = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};
   uint16 key_c[8];

   // complement the key
   for(int i=0;i<8;i++) key_c[i]  = !key[i];
   // complement the data
   for(int i=0;i<4;i++) data_c[i] = !data[i];

   // test to see if complement property
   // of DES exists, ie c=fortress(p,k)
   //                   c'=fortress(p',k')
   fortress(data,1,key);     // data now holds the cipher text
   //encrypt the complements
   fortress(data_c,1,key_c); // is the cipher text the complement of itself ?

   for(int i=0;i<4;i++)
           if(data[i] == !data_c[i])
               printf("algorithm insecure\n"); // this property not true for fortress
   printf("%x\t%x\t%x\t%x\t\n",data[0],data[1],data[2],data[3]);
   printf("%x\t%x\t%x\t%x\t\n",data_c[0],data_c[1],data_c[2],data_c[3]);

}
#endif

void Fortress(const char *pass, const char *file, uint32 *data,size_t size,bool mode)
{
      uint16 *ek, *dk;
      if((size % 2) != 0) {
          fprintf(stderr,"This implementation of fortress uses blocks of 64bits\n");
          fprintf(stderr,"Data must be a multiple of two uint32's\n");
          exit(-6);
      }
      if(mode == ENCRYPT) {
          /* encrypt */
          ek=KeyCreate();
          KeySchedule(ek);
          fortress(data,size,ek);
          KeySave(pass, file,ek);
          KeyDestroy(ek);
      }
      else {
           /* decrypt */
           ek=KeyCreate();
           dk=KeyCreate();
           KeyRestore(pass, file, ek);
           KeyInverse(ek,dk);
           KeyDestroy(ek);
           fortress(data,size,dk);
           KeyDestroy(dk);
      }
}/* Fortress() */

void fortress(uint32 *data,size_t size,uint16 *k)
{
    uint32 i,j,L,L1,R,R1;
    /*
     * fiestal network
     */
    for(i=0;i<size; i+=2) {
        /* split each block into two, L and R
         */
         L =  data[i];
         R =  data[i+1];
         for(j=0; j < ROUNDS; j++) {
           L1  = R; /* save R for later swapping */
           R1  = L ^ f(R,k);
           L   = L1;
           R   = R1;
           L1  = R1 = 0;
         }
         data[i]   =  R;
         data[i+1] =  L;
    }
    
}/* fortress() */


uint32 f(uint32 R, uint16 *key)
{

    uint16    a,b,c,d,e,f,g,h,i,j,k,l,m,n,o;
    union sblock rblck;
    rblck.blck = R;

    a = multiply(rblck.b[0],key[0]);
    b = add (rblck.b[0],key[1]);
    c = rblck.b[0] ^ key[2];

    d = multiply(rblck.b[1],key[3]);
    e = add (rblck.b[1],key[4]);
    f = rblck.b[1] ^ key[5];

    g = a ^ e;
    h = b ^ d;
    i = multiply(c,f);

    j = add(g,i);
    k = add(h,i);

    l = multiply(j,key[6]);
    m = multiply(k,key[7]);

    n = l ^ k;
    o = m ^ j;

    rblck.b[0] = n;
    rblck.b[1] = o;

    return (rblck.blck);

}/* f() */

uint16 *KeyCreate(void)
{
     uint16  *k;
     k = new uint16[NOPERATIONS];
     return (k);
}/* KeyCreate() */

void KeySchedule(uint16 *k)
{
    // Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
      char *error = strerror(errno);
      fprintf(stderr," ERROR OPENING URANDOM DEVICE [%s]\n", error);
      exit(-7);
    } else {
      ssize_t bytes = sizeof(uint16) * NOPERATIONS;
      ssize_t bytes_in = read(fd, k, bytes);
      if (bytes_in != bytes) {
        char *error = strerror(errno);
        fprintf(stderr, " ERROR READING FROM URANDOM DEVICE [%s]\n", error);
        exit(-8);
      }
    }
    close(fd);
}/* KeySchedule() */

void KeyDestroy(uint16 *k)
{
     uint16 i;
     if(k!=NULL) {
         for(i=0;i<NOPERATIONS;i++)
                k[i]=0x0;
         delete[] k;
     }
}/* KeyDestroy() */

void KeyInverse(uint16 *ek,uint16 *dk)
{

    dk[0] = ek[0];
    dk[1] = ek[1];
    dk[2] = ek[2];
    dk[3] = ek[3];
    dk[4] = ek[4];
    dk[5] = ek[5];
    dk[6] = ek[6];
    dk[7] = ek[7];

}/* KeyInverse() */

void cipher_key(const char *pass, bool mode, uint16 *k)
{
   char *key = (char *)k;
   int ops = NOPERATIONS * 2;
   for(int j = 0; j < ops; ++j) {
     for(int i = 0; i < strlen(pass); ++i) {
        key[j] ^= pass[i];
     }
   }
}/* cipher_key() */

void KeySave(const char *pass, const char *file, uint16 *k)
{
   uint16   i;
   FILE   *fp;

   char *keysave = strdup(file);
   strcat(keysave, ".key");
   fp = fopen(keysave,"wb");
   cipher_key(pass, ENCRYPT, k);
   if(fp != NULL) {
      for(i=0;i<NOPERATIONS;i++)
          fprintf(fp,"%d\t",k[i]);
      fclose(fp);
   }
   free((void *)keysave);
}/* KeySave() */

void KeyRestore(const char *pass, const char *file, uint16 *k)
{
    uint16 i;
    FILE *fp;

    char *keysave = strdup(file);
    strcat(keysave, ".key");
    fp = fopen(keysave,"rb");
    if(fp != NULL) {
         for(i=0;i<NOPERATIONS;i++)
            fscanf(fp,"%hd",&k[i]);
         fclose(fp);
    }
    cipher_key(pass, DECRYPT, k);
    free((void *)keysave);
}/* KeyRestore() */

/////math functions follow  //////////////////////////////////////////////////////

//addition modulo 65536
uint16 add(sint32 a, sint32 b)
{
  return (uint16)((a + b) % 65536l);
}/* add() */

//This function is used in the IdeaKeyInversion function
uint16 addinv(uint16 x)
{
	return 0-x;
}/* addinv() */

//multiplication modulo 65537
uint16 multiply(sint32 a, sint32 b)
{
  sint32 ch, cl, c;

  if (a == 0) a = 65536l;
  if (b == 0) b = 65536l;
  c = a * b;
  if (c) {
	 ch = (c >> 16) & 65535l;
	 cl = c & 65535l;
	 if (cl >= ch) return (uint16) (cl - ch);
	 return (uint16) ((cl - ch + 65537l) & 65535l);
  }
  if (a == b) return 1;
  return 0;
}/* multiply() */
