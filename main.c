/* HiddenKernel PLDMGR Install & Update v0.2.0-beta.
 * Official itsPLK release, asset digest, bounded downloads, preserved autoload.
 * Manual invocation only. No other payloads executed and no USB changes.
 */
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "assets_cacert_pem.h"
#ifndef AUTOLOADER_DIR
#define AUTOLOADER_DIR "/data/ps5_autoloader"
#endif
#define APP "PLDMGR Install & Update 0.2.0-beta"
#define RELEASE_API "https://api.github.com/repos/itsPLK/ps5-payload-manager/releases/latest"
#define RELEASE_PREFIX "https://github.com/itsPLK/ps5-payload-manager/releases/download/"
#define ELF AUTOLOADER_DIR "/pldmgr.elf"
#define BACKUP AUTOLOADER_DIR "/pldmgr.elf.bak"
#define AUTOLOAD AUTOLOADER_DIR "/autoload.txt"
#define VERSION AUTOLOADER_DIR "/pldmgr.version"
#define LOCK AUTOLOADER_DIR "/.hkl-update.lock"
#define MAX_ELF (32u*1024u*1024u)
#define MIN_ELF (64u*1024u)
#define MAX_JSON (2u*1024u*1024u)
#define MAX_AUTOLOAD (256u*1024u)
typedef struct { char unused[45]; char message[3075]; } notify_request_t;
extern int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);
static void notify(const char *fmt, ...) {
    notify_request_t r = {0}; va_list ap; va_start(ap,fmt);
    vsnprintf(r.message,sizeof r.message,fmt,ap); va_end(ap);
    sceKernelSendNotificationRequest(0,&r,sizeof r,0);
}
/* A small strict JSON scanner; fields are found in the actual object, not in
 * escaped release notes or neighbouring assets. No general-purpose decoding
 * needed: all accepted tag/name/URL/digest values must be unescaped ASCII. */
typedef struct { const char *a,*b; } span;
static const char *ws(const char *p,const char *e) { while(p<e && isspace((unsigned char)*p))p++; return p; }
static const char *skip(const char *p,const char *e,unsigned depth) {
    p=ws(p,e); if(p==e || depth>48)return NULL;
    if(*p=='"') { for(++p;p<e;p++){ if(*p=='"')return p+1; if(*p=='\\'){if(++p==e)return NULL;} else if((unsigned char)*p<32)return NULL; } return NULL; }
    if(*p=='{' || *p=='[') { int obj=*p=='{'; char close=obj?'}':']'; p=ws(p+1,e); if(p<e&&*p==close)return p+1;
        for(;;){ if(obj){if(p==e||*p!='"')return NULL; p=skip(p,e,depth+1); if(!p)return NULL; p=ws(p,e);if(p==e||*p!=':')return NULL;p++;}
            p=skip(p,e,depth+1); if(!p)return NULL;p=ws(p,e);if(p==e)return NULL;if(*p==close)return p+1;if(*p!=',')return NULL;p=ws(p+1,e); }
    }
    const char *a=p;while(p<e&&!isspace((unsigned char)*p)&&*p!=','&&*p!=']'&&*p!='}')p++;return p>a?p:NULL;
}
static int equal(span x,const char *v) { return x.a&&x.b-x.a==(ptrdiff_t)strlen(v)&&memcmp(x.a,v,strlen(v))==0; }
static span field(span obj,const char *key) {
    span none={0}; const char *p=ws(obj.a,obj.b); if(p==obj.b||*p!='{')return none;
    p=ws(p+1,obj.b); span result={0};
    while(p<obj.b&&*p!='}') { const char *k=p; const char *end=skip(p,obj.b,0);if(!end||*k!='"')return none;
        p=ws(end,obj.b);if(p==obj.b||*p!=':')return none;p=ws(p+1,obj.b);const char *v=skip(p,obj.b,0);if(!v)return none;
        if(end-k==(ptrdiff_t)strlen(key)+2&&!memcmp(k+1,key,strlen(key))) {if(result.a)return none;result=(span){p,v};}
        p=ws(v,obj.b);if(p<obj.b&&*p==',')p=ws(p+1,obj.b);else break;
    } return result;
}
static int string(span x,char *out,size_t n) {
    if(!x.a||x.b-x.a<2||*x.a!='"'||x.b[-1]!='"'||(size_t)(x.b-x.a-2)>=n)return -1;
    size_t len=(size_t)(x.b-x.a-2);for(size_t i=0;i<len;i++){unsigned char c=x.a[i+1];if(c<32||c>126||c=='\\'||c=='"')return -1;}memcpy(out,x.a+1,len);out[len]=0;return 0;
}
static int tag_ok(const char *s) { if(!*s)return 0; for(;*s;s++)if(!isalnum((unsigned char)*s)&&*s!='.'&&*s!='-'&&*s!='_')return 0;return 1; }
static int hex_digest(const char *s) { if(strlen(s)!=71||strncmp(s,"sha256:",7))return 0;for(s+=7;*s;s++)if(!isxdigit((unsigned char)*s))return 0;return 1; }
static int select_release(const char *json,size_t n,char tag[128],char url[1024],char sha[65]) {
    const char *end=json+n,*start=ws(json,end),*tail=skip(start,end,0);if(!tail||ws(tail,end)!=end)return -1;span root={start,tail};
    if(!equal(field(root,"draft"),"false")||!equal(field(root,"prerelease"),"false")||string(field(root,"tag_name"),tag,128)||!tag_ok(tag))return -1;
    span a=field(root,"assets");if(!a.a||*a.a!='[')return -1;const char *p=ws(a.a+1,a.b);int count=0;
    char wanted[180],expected[1024];int nn=snprintf(wanted,sizeof wanted,"pldmgr_%s.elf",tag);if(nn<0||(size_t)nn>=sizeof wanted)return -1;
    while(p<a.b&&*p!=']') {const char *q=skip(p,a.b,0);if(!q)return -1;span x={p,q};char name[180],candidate[1024],digest[72];
        if(!string(field(x,"name"),name,sizeof name)&&(!strcmp(name,wanted)||!strcmp(name,"pldmgr.elf"))) {
            if(++count!=1||!equal(field(x,"state"),"\"uploaded\"")||string(field(x,"browser_download_url"),candidate,sizeof candidate)||string(field(x,"digest"),digest,sizeof digest)||!hex_digest(digest))return -1;
            int k=snprintf(expected,sizeof expected,"%s%s/%s",RELEASE_PREFIX,tag,name);if(k<0||(size_t)k>=sizeof expected||strcmp(candidate,expected))return -1;
            strcpy(url,candidate);for(int i=0;i<64;i++)sha[i]=(char)tolower((unsigned char)digest[i+7]);sha[64]=0;
        }
        p=ws(q,a.b);if(p<a.b&&*p==',')p=ws(p+1,a.b);else break;
    }return count==1?0:-1;
}
typedef struct { unsigned char *data;size_t len,limit; } buffer;
static size_t receive(void *p,size_t s,size_t n,void *ctx) {
    buffer *b=ctx;if(s&&n>SIZE_MAX/s)return 0;size_t k=s*n;if(k>b->limit-b->len)return 0;
    unsigned char *next=realloc(b->data,b->len+k+1);if(!next)return 0;b->data=next;memcpy(b->data+b->len,p,k);b->len+=k;b->data[b->len]=0;return k;
}
static int download(const char *url,buffer *b) {
    CURL *c=curl_easy_init(); if(!c)return -1; char err[CURL_ERROR_SIZE]={0}; long http=0;
    struct curl_blob ca={(void *)hk_cacert_pem,hk_cacert_pem_len,CURL_BLOB_COPY};
    curl_easy_setopt(c,CURLOPT_URL,url);curl_easy_setopt(c,CURLOPT_USERAGENT,"HiddenKernel-PLDMGR/0.2.0-beta");
    curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1L);curl_easy_setopt(c,CURLOPT_MAXREDIRS,5L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(c,CURLOPT_PROTOCOLS_STR,"https");curl_easy_setopt(c,CURLOPT_REDIR_PROTOCOLS_STR,"https");
#else
    curl_easy_setopt(c,CURLOPT_PROTOCOLS,(long)CURLPROTO_HTTPS);curl_easy_setopt(c,CURLOPT_REDIR_PROTOCOLS,(long)CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(c,CURLOPT_CONNECTTIMEOUT,15L);curl_easy_setopt(c,CURLOPT_TIMEOUT,120L);curl_easy_setopt(c,CURLOPT_ERRORBUFFER,err);
    curl_easy_setopt(c,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(c,CURLOPT_SSL_VERIFYHOST,2L);
    if(curl_easy_setopt(c,CURLOPT_CAINFO_BLOB,&ca)!=CURLE_OK){curl_easy_cleanup(c);notify("%s: no se pudo configurar TLS.",APP);return -1;}
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,receive);curl_easy_setopt(c,CURLOPT_WRITEDATA,b);curl_easy_setopt(c,CURLOPT_MAXFILESIZE_LARGE,(curl_off_t)b->limit);
    CURLcode rc=curl_easy_perform(c);curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&http);curl_easy_cleanup(c);
    if(rc!=CURLE_OK||http<200||http>=300){
        if(rc==CURLE_COULDNT_RESOLVE_HOST)notify("%s: DNS no responde; si usas 127.0.0.1, inicia tu DNS local y reintenta.",APP);
        else if(rc==CURLE_PEER_FAILED_VERIFICATION||rc==CURLE_SSL_CONNECT_ERROR)notify("%s: error TLS; comprueba fecha/hora y certificados.",APP);
        else notify("%s: fallo de red/HTTP %ld (%s).",APP,http,err[0]?err:curl_easy_strerror(rc));
        return -1;
    }return b->len?0:-1;
}
static int sha256(const unsigned char *data,size_t n,char out[65]) {
    unsigned char hash[32];
#if MBEDTLS_VERSION_MAJOR >= 3
    if(mbedtls_sha256(data,n,hash,0)!=0)return -1;
#else
    if(mbedtls_sha256_ret(data,n,hash,0)!=0)return -1;
#endif
    static const char hex[]="0123456789abcdef";for(size_t i=0;i<32;i++){out[2*i]=hex[hash[i]>>4];out[2*i+1]=hex[hash[i]&15];}out[64]=0;return 0;
}
static int valid_elf(const buffer *b,const char *sha) {
    char got[65];return b->len>=MIN_ELF&&b->len<=MAX_ELF&&!memcmp(b->data,"\177ELF\002\001",6)&&b->data[18]==0x3e&&b->data[19]==0&&!sha256(b->data,b->len,got)&&!strcmp(sha,got);
}
/* Returns 1 if missing, -1 if unreadable/unsafe, 0 if read. */
static int read_local(const char *path,buffer *b) {
    struct stat st;if(lstat(path,&st)){return errno==ENOENT?1:-1;}if(!S_ISREG(st.st_mode)||st.st_size<0||(uintmax_t)st.st_size>b->limit)return -1;
    FILE *f=fopen(path,"rb");if(!f)return -1;b->data=malloc((size_t)st.st_size+1);if(!b->data){fclose(f);return -1;}b->len=fread(b->data,1,(size_t)st.st_size,f);int ok=b->len==(size_t)st.st_size&&!ferror(f)&&fgetc(f)==EOF;fclose(f);b->data[b->len]=0;return ok?0:-1;
}
static int write_atomic(const char *path,const void *data,size_t n,mode_t mode) {
    char tmp[512];int z=snprintf(tmp,sizeof tmp,"%s.tmp.XXXXXX",path);if(z<0||(size_t)z>=sizeof tmp)return -1;int fd=mkstemp(tmp);if(fd<0)return -1;
    FILE *f=fdopen(fd,"wb");if(!f){close(fd);unlink(tmp);return -1;}int ok=fwrite(data,1,n,f)==n&&!fflush(f)&&!fsync(fd)&&!fchmod(fd,mode);if(fclose(f))ok=0;
    if(ok&&!rename(tmp,path))return 0;
    unlink(tmp);return -1;
}
/* Preserve every original byte. Recognise existing manager entries, including
 * versioned or relative paths, and refuse ambiguous configurations. */
static int autoload_status(const buffer *b) {
    size_t pos=0;int seen=0;
    if(b->len&&memchr(b->data,0,b->len))return -1;
    while(pos<b->len){size_t end=pos;while(end<b->len&&b->data[end]!='\n')end++;size_t a=pos,z=end;while(a<z&&isspace(b->data[a]))a++;while(z>a&&isspace(b->data[z-1]))z--;
        if(a<z&&b->data[a]!='#'&&b->data[a]!=';'&&b->data[a]!='!'){size_t base=a;for(size_t k=a;k<z;k++)if(b->data[k]=='/')base=k+1;size_t n=z-base;
            if(n>=10&&!memcmp(b->data+base,"pldmgr",6)&&!memcmp(b->data+z-4,".elf",4)){
                if(n!=10||memcmp(b->data+base,"pldmgr.elf",10)||++seen>1)return -1;
                if(base!=a&&!(base-a==2&&!memcmp(b->data+a,"./",2))&&!(z-a==strlen(ELF)&&!memcmp(b->data+a,ELF,z-a)))return -1;
            }
        }pos=end+1;
    }return seen;
}
static int ensure_autoload(const buffer *old,int missing) {
    int status=autoload_status(old);if(status<0)return -1;if(status)return 0;
    if(missing)return write_atomic(AUTOLOAD,"!3000\npldmgr.elf\n",strlen("!3000\npldmgr.elf\n"),0644);
    const char *suffix=old->len&&old->data[old->len-1]!='\n'?"\npldmgr.elf\n":"pldmgr.elf\n";size_t n=strlen(suffix);unsigned char *out=malloc(old->len+n);if(!out)return -1;
    if(old->len)memcpy(out,old->data,old->len);
    memcpy(out+old->len,suffix,n);int rc=write_atomic(AUTOLOAD,out,old->len+n,0644);free(out);return rc;
}
int main(void) {
    int rc=1,fd=-1,curl_ready=0;char tag[128],url[1024],sha[65];
    buffer json={.limit=MAX_JSON},local={.limit=MAX_ELF},fresh={.limit=MAX_ELF},auto_old={.limit=MAX_AUTOLOAD},auto_now={.limit=MAX_AUTOLOAD};
    notify("%s: comprobando versión oficial...",APP);
    if(mkdir(AUTOLOADER_DIR,0755)&&errno!=EEXIST){notify("%s: no se pudo crear carpeta.",APP);goto done;}
    struct stat dir;if(lstat(AUTOLOADER_DIR,&dir)||!S_ISDIR(dir.st_mode)){notify("%s: ruta de autoloader inválida.",APP);goto done;}
    fd=open(LOCK,O_CREAT|O_RDWR|O_NOFOLLOW,0600);struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET};if(fd<0||fcntl(fd,F_SETLK,&lock)){notify("%s: otro actualizador activo o bloqueo no disponible.",APP);goto done;}
    int am=read_local(AUTOLOAD,&auto_old);if(am<0||autoload_status(&auto_old)<0){notify("%s: autoload no legible o contiene otra entrada PLDMGR; revisar manualmente. Sin cambios.",APP);goto done;}
    int lm=read_local(ELF,&local);if(lm<0){notify("%s: ELF local no legible; sin cambios.",APP);goto done;}
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK)goto done;
    curl_ready=1;
    if(download(RELEASE_API,&json))goto done;
    if(select_release((const char *)json.data,json.len,tag,url,sha)){notify("%s: release oficial ambigua o sin SHA-256; sin cambios.",APP);goto done;}
    int need=lm==1||!valid_elf(&local,sha);
    if(need){if(download(url,&fresh))goto done;if(!valid_elf(&fresh,sha)){notify("%s: ELF o SHA-256 incorrecto; se conserva el original.",APP);goto done;}}
    /* Check that configuration did not change while downloading. */
    int now=read_local(AUTOLOAD,&auto_now);if(now!=am||auto_now.len!=auto_old.len||(auto_old.len&&memcmp(auto_old.data,auto_now.data,auto_old.len))){notify("%s: autoload cambió durante la operación; reintentar.",APP);goto done;}
    if(need){if(lm==0&&write_atomic(BACKUP,local.data,local.len,0755)){notify("%s: no se pudo respaldar ELF anterior; sin cambios.",APP);goto done;}
        if(write_atomic(ELF,fresh.data,fresh.len,0755)){notify("%s: instalación fallida; se conserva original.",APP);goto done;}}
    if(ensure_autoload(&auto_old,am==1)){notify("%s: ELF validado; no se pudo actualizar autoload. Revisar manualmente.",APP);goto done;}
    char v[140];snprintf(v,sizeof v,"%s\n",tag);if(write_atomic(VERSION,v,strlen(v),0644))notify("%s: instalado; marcador de versión no guardado.",APP);
    notify("%s: %s %s. Autoload conservado. Si arrancas desde USB, revisa su configuración aparte.",APP,tag,need?"instalado":"ya verificado");rc=0;
done:
    free(json.data);free(local.data);free(fresh.data);free(auto_old.data);free(auto_now.data);if(curl_ready)curl_global_cleanup();if(fd>=0)close(fd);return rc;
}
