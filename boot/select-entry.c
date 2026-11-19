/* SPDX-License-Identifier: MIT
 * x86-64 UEFI adapter: one explicit menu choice, then the authoritative loader.
 * UEFI 2.x table/protocol ABI; no libc, filesystem writes or persistent defaults.
 */
typedef unsigned long long U;
typedef unsigned int U32;
typedef unsigned short C;
typedef unsigned char B;
typedef struct { U32 a; C b,c; B d[8]; } GUID;
typedef struct { U sig; U32 rev,size,crc,reserved; } HEADER;
typedef struct { HEADER h; void *fn[44]; } SERVICES;
typedef struct { HEADER h; C *vendor; U32 revision; void *in_handle,*in,*out_handle,*out,*err_handle,*err; SERVICES *rt,*bs; U count; void *tables; } SYSTEM;
typedef struct { U32 revision; void *parent; SYSTEM *system; void *device,*path,*reserved; U32 options_size; C *options; void *base; U size; U32 code_type,data_type; void *unload; } IMAGE;
static GUID image_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID path_guid={0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static GUID loader_guid={0x4a67b082,0x0a4c,0x41cf,{0xb6,0xc7,0x44,0x0b,0x29,0xbb,0x8c,0x4f}};
static GUID recovery_guid={0xdac8e170,0x20d1,0x4c6d,{0x9e,0x2f,0x56,0xd0,0x3a,0x6f,0x71,0x93}};
#define ERROR(n) (0x8000000000000000ULL | (n))
typedef U (*PROTOCOL)(void*,GUID*,void**);
typedef U (*ALLOC)(U32,U,void**);
typedef U (*FREE)(void*);
typedef U (*GET)(C*,GUID*,U32*,U*,void*);
typedef U (*SET)(C*,GUID*,U32,U,void*);
typedef U (*LOAD)(B,void*,void*,void*,U,void**);
typedef U (*START)(void*,U*,C**);
typedef struct EFI_FILE { U revision; void *fn[14]; } EFI_FILE;
typedef struct { U revision; void *open; } FS;
typedef U (*OPEN_VOLUME)(FS*,EFI_FILE**);
typedef U (*OPEN_EFI_FILE)(EFI_FILE*,EFI_FILE**,C*,U,U);
typedef U (*READ_EFI_FILE)(EFI_FILE*,U*,void*);
typedef U (*CLOSE_EFI_FILE)(EFI_FILE*);
static GUID fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static B config_bytes[4097];
static B equal(C *a,C *b,U bound) {
 for(U i=0;i<bound;i++) {if(a[i]!=b[i])return 0;if(!a[i])return 1;}
 return 0;
}
static B suffix(C *entry,U n,C *tail,U length) {
 if(n<length)return 0;
 for(U i=0;i<length;i++)if(entry[n-length+i]!=tail[i])return 0;
 return n==length || entry[n-length-1]=='-';
}
/* Read the actual default on this ESP, including changes made by offline recovery.
 * The graphical menu never caches a root/generation identity for kernel choices. */
static U choose_entry(SYSTEM *st,void *device,U mode,C *entry,U *length) {
 FS *fs=0;EFI_FILE *root=0,*file=0;U status=((PROTOCOL)st->bs->fn[16])(device,&fs_guid,(void**)&fs);
 if(status)return status;
 status=((OPEN_VOLUME)fs->open)(fs,&root);if(status)return status;
 status=((OPEN_EFI_FILE)root->fn[0])(root,&file,L"\\loader\\loader.conf",1,0);if(status)goto done;
 U size=sizeof(config_bytes);status=((READ_EFI_FILE)file->fn[3])(file,&size,config_bytes);
 ((CLOSE_EFI_FILE)file->fn[1])(file);file=0;
 if(status)goto done;
 if(size>=sizeof(config_bytes)){status=ERROR(4);goto done;}
 U n=0,found=0;
 for(U start=0;start<size;) {
  U end=start;while(end<size && config_bytes[end]!='\n')end++;
  U i=start;while(i<end && (config_bytes[i]==' '||config_bytes[i]=='\t'))i++;
  static B key[]="default";U j=0;while(j<7 && i+j<end && config_bytes[i+j]==key[j])j++;
  if(j==7 && i+j<end && (config_bytes[i+j]==' '||config_bytes[i+j]=='\t')) {
   if(found++){status=ERROR(2);goto done;}
   i+=7;while(i<end && (config_bytes[i]==' '||config_bytes[i]=='\t'))i++;
   for(;i<end && config_bytes[i]!=' ' && config_bytes[i]!='\t' && config_bytes[i]!='\r';i++) {
    B c=config_bytes[i];if(n>=240 || !((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.')){status=ERROR(2);goto done;}
    entry[n++]=c;
   }
   while(i<end && (config_bytes[i]==' '||config_bytes[i]=='\t'||config_bytes[i]=='\r'))i++;
   if(i!=end){status=ERROR(2);goto done;}
  }
  start=end+1;
 }
 if(found!=1){status=ERROR(2);goto done;}
 U base;
 if(suffix(entry,n,L"linux-lts.conf",14))base=n-14;
 else if(suffix(entry,n,L"linux.conf",10))base=n-10;
 else {status=ERROR(2);goto done;}
 if(mode==2) {
  /* The independent recovery environment, when installed, replaces the
   * recovery screen that runs from the installed root. */
  static C env[]=L"enzimos-recovery-env.conf";
  status=((OPEN_EFI_FILE)root->fn[0])(root,&file,L"\\loader\\entries\\enzimos-recovery-env.conf",1,0);
  if(!status) {
   ((CLOSE_EFI_FILE)file->fn[1])(file);
   for(n=0;env[n];n++)entry[n]=env[n];
   entry[n]=0;*length=n;goto done;
  }
 }
 if(mode<2) {
  C *tail=mode==1?L"linux-lts.conf":L"linux.conf";n=base;
  while(*tail)entry[n++]=*tail++;
 }
 entry[n]=0;*length=n;
 C path[300];C *prefix=L"\\loader\\entries\\";U k=0;
 while(*prefix)path[k++]=*prefix++;
 for(U i=0;i<=n;i++)path[k+i]=entry[i];
 status=((OPEN_EFI_FILE)root->fn[0])(root,&file,path,1,0);
 if(!status)((CLOSE_EFI_FILE)file->fn[1])(file);
 done:((CLOSE_EFI_FILE)root->fn[1])(root);return status;
}
U efi_main(void *self,SYSTEM *st) {
 IMAGE *im=0; U status=((PROTOCOL)st->bs->fn[16])(self,&image_guid,(void**)&im);
 if(status)return status;
 if(!im->options || im->options_size<4 || im->options_size>520 || im->options_size%2)return ERROR(2);
 C entry[260];U n=0,mode;
 if(equal(im->options,L"linux",im->options_size/2))mode=0;
 else if(equal(im->options,L"linux-lts",im->options_size/2))mode=1;
 else if(equal(im->options,L"recovery",im->options_size/2))mode=2;
 else if(equal(im->options,L"recovery-console",im->options_size/2))mode=3;
 else return ERROR(2);
 B recovery=mode>=2;
 C *recovery_variable=mode==3?L"EnzimosRecoveryConsole":L"EnzimosRecoveryUI";
 GET get=(GET)st->rt->fn[6]; SET set=(SET)st->rt->fn[8]; U size=0;
 status=get(L"LoaderEntryOneShot",&loader_guid,0,&size,0);
 /* A previously staged recovery wins; don't silently discard its one-shot. */
 if(status!=ERROR(14))return ERROR(15);
 status=choose_entry(st,im->device,mode,entry,&n);if(status)return status;
 B *device_path=0;status=((PROTOCOL)st->bs->fn[16])(im->device,&path_guid,(void**)&device_path);if(status)return status;
 U prefix=0;
 while(prefix<4096) { B *p=device_path+prefix; U len=p[2]|((U)p[3]<<8); if(len<4 || prefix+len>4096)return ERROR(2);if(p[0]==0x7f&&p[1]==0xff)break;prefix+=len; }
 if(prefix>=4096)return ERROR(2);
 static C path[]=L"\\EFI\\systemd\\systemd-bootx64.efi";
 U node=4+sizeof(path); B *combined=0;
 status=((ALLOC)st->bs->fn[5])(2,prefix+node+4,(void**)&combined);if(status)return status;
 for(U i=0;i<prefix;i++)combined[i]=device_path[i];
 combined[prefix]=4;combined[prefix+1]=4;combined[prefix+2]=node&255;combined[prefix+3]=node>>8;
 for(U i=0;i<sizeof(path);i++)combined[prefix+4+i]=((B*)path)[i];
 combined[prefix+node]=0x7f;combined[prefix+node+1]=0xff;combined[prefix+node+2]=4;combined[prefix+node+3]=0;
 void *child=0;status=((LOAD)st->bs->fn[22])(0,self,combined,0,0,&child);
 ((FREE)st->bs->fn[6])(combined);if(status)return status;
 status=set(L"LoaderEntryOneShot",&loader_guid,7,(n+1)*2,entry);if(status)return status;
 if(recovery) {B value=1;status=set(recovery_variable,&recovery_guid,6,1,&value);if(status){set(L"LoaderEntryOneShot",&loader_guid,7,0,0);return status;}}
 status=((START)st->bs->fn[23])(child,0,0);
 set(L"LoaderEntryOneShot",&loader_guid,7,0,0);
 if(recovery)set(recovery_variable,&recovery_guid,6,0,0);
 return status;
}
