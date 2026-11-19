/* Contract tests for actual EFI selector parsing; firmware call sites are mocked. */
#include <assert.h>
#include <string.h>
#include "../boot/select-entry.c"
static const char *text;
static B recovery_present;
static EFI_FILE root,file;
static FS fs;
static U close_file(EFI_FILE *f) {(void)f;return 0;}
static U read_file(EFI_FILE *f,U *n,void *out) {(void)f;U len=strlen(text);if(*n>len)*n=len;memcpy(out,text,*n);return 0;}
static U open_file(EFI_FILE *f,EFI_FILE **out,C *path,U mode,U attr) {
 (void)f;assert(mode==1 && attr==0);
 if(equal(path,L"\\loader\\entries\\enzimos-recovery-env.conf",300) && !recovery_present)return ERROR(14);
 *out=&file;return 0;
}
static U open_volume(FS *f,EFI_FILE **out) {(void)f;*out=&root;return 0;}
static U protocol(void *device,GUID *guid,void **out) {(void)device;assert(guid==&fs_guid);*out=&fs;return 0;}
static void check(SYSTEM *st,const char *config,U mode,C *expected) {
 C entry[260];U n=0;text=config;U status=choose_entry(st,0,mode,entry,&n);
 if(expected){assert(status==0);assert(equal(entry,expected,n+1));}else assert(status!=0);
}
int main(void) {
 SERVICES bs={0};SYSTEM st={0};st.bs=&bs;bs.fn[16]=protocol;fs.open=open_volume;
 root.fn[0]=open_file;root.fn[1]=close_file;file.fn[1]=close_file;file.fn[3]=read_file;
 check(&st,"timeout menu-disabled\ndefault linux.conf\n",1,L"linux-lts.conf");
 check(&st,"default linux-lts.conf\n",0,L"linux.conf");
 check(&st,"# old default linux.conf\ndefault enzimos-staged-ui-123-linux.conf\n",1,L"enzimos-staged-ui-123-linux-lts.conf");
 check(&st,"default enzimos-new-root-linux-lts.conf\n",2,L"enzimos-new-root-linux-lts.conf");
 check(&st,"default enzimos-new-root-linux-lts.conf\n",3,L"enzimos-new-root-linux-lts.conf");
 recovery_present=1;
 check(&st,"default enzimos-new-root-linux-lts.conf\n",2,L"enzimos-recovery-env.conf");
 recovery_present=0;
 check(&st,"default linux.conf\ndefault other-linux.conf\n",0,0);
 check(&st,"default ../linux.conf\n",0,0);
 check(&st,"default unknown.conf\n",0,0);
 check(&st,"timeout 0\n",0,0);
 check(&st,"default linux.conf evil\n",0,0);
 C bad[3]={'a','b','c'};assert(!equal(bad,L"abc",3));
 return 0;
}
