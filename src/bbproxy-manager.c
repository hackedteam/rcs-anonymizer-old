#include "bbproxy.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

extern int ifd[2];

#define NET_OK 0x000F0001
#define NET_NO 0x000F0002
#define NET_BYE 0x000F0003

struct netheader {
   uint32_t code;
   uint32_t len;
} __attribute__((__packed__));

#define NET_LOGIN 0x000F0004
struct netlogin {
   char signature[32];
} __attribute__((__packed__));

#define NET_VERSION 0x000F0008
struct netversion {
   char version[16];
} __attribute__((__packed__));

#define NET_MONITOR 0x000F0005
struct netmonitor {
   char status[16];
   uint32_t disk;
   uint32_t cpu;
   uint32_t pcpu;
   char desc[1024];
} __attribute__((__packed__));

#define NET_CONFIG 0x000F0006
struct netconfig {
   char filename[260];
   uint32_t filesize;
} __attribute__((__packed__));

#define NET_UPGRADE 0x000F0009
struct netupgrade {
   char filename[260];
   uint32_t filesize;
} __attribute__((__packed__));

#define NET_LOG 0x000F0007
struct netlog {
   struct {
      int tm_sec;
      int tm_min;
      int tm_hour;
      int tm_mday;
      int tm_mon;
      int tm_year;
      int tm_wday;
      int tm_yday;
      int tm_isdst;
   } t;
   uint32_t level;
   char desc[1024];
} __attribute__((__packed__));

int netwrite(BIO *bio, uint32_t code, void *msg, uint32_t len);
int netread(BIO *bio, uint32_t *code, void *msg, uint32_t len);
int netreadfile(BIO *bio, char *filename, uint32_t filesize);
int managerhandler(BIO *cbio);
int getcpustat(uint64_t *cpusum, uint64_t *cpuidle);

int netwrite(BIO *bio, uint32_t code, void *msg, uint32_t len)
{
   if(BIO_write(bio, &code, sizeof(code)) != sizeof(code)) return -1;
   if(BIO_write(bio, &len, sizeof(len)) != sizeof(len)) return -1;

   if(len && msg) if(BIO_write(bio, msg, len) != len) return -1;

   if(BIO_flush(bio) != 1) return -1;

   return 0;
}

int netread(BIO *bio, uint32_t *code, void *msg, uint32_t len)
{
   struct netheader h;
   int ret, recv;

   if(BIO_read(bio, &h, sizeof(h)) != sizeof(h)) return -1;

   *code = h.code;

   if(h.len != len) return 1;

   recv = 0;
   while(recv != len) {
      if((ret = BIO_read(bio, (char *)msg + recv, len - recv)) < 1) return -1;
      recv += ret;
   }

   return 0;
}

int netreadfile(BIO *bio, char *filename, uint32_t filesize)
{
   int ret;
   char buf[1024];
   FILE *fp;

   if(!(fp = fopen(filename, "w"))) return -1;

   while(filesize) {
      if((ret = BIO_read(bio, buf, (filesize > sizeof(buf)) ? sizeof(buf) : filesize)) < 1) {
         fclose(fp);
         unlink(filename);

         return -1;
      }

      if(fwrite(buf, ret, 1, fp) != 1) {
         fclose(fp);
         unlink(filename);

         return -1;
      }

      filesize -= ret;
   }

   fclose(fp);

   return 0;
}

int managerhandler(BIO *cbio)
{
   BIO *sbio = NULL;
   int cfd, len = 0, i, cmd, wantupgrade = 0;
   struct sockaddr_in caddr;
   SSL_CTX *ctx;

   uint32_t code;
   struct netlogin nlogin;
   struct netversion nversion;
   struct netmonitor nmonitor;
   struct netconfig nconfig;
   struct netupgrade nupgrade;
   struct netlog nlog;

   struct log l;
   struct tm t;
   struct statvfs vfs;

   uint64_t cpusum1, cpuidle1, cpusum2, cpuidle2;

   cfd = BIO_get_fd(cbio, NULL);
   len = sizeof(caddr);
   getpeername(cfd, (struct sockaddr *)&caddr, (socklen_t *)&len);

   SSL_library_init();

   ctx = SSL_CTX_new(SSLv23_server_method());
   SSL_CTX_use_certificate_chain_file(ctx, CERTIFICATE_FILE);
   SSL_CTX_use_PrivateKey_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM);
   SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

   sbio = BIO_new_ssl(ctx, 0);
   BIO_push(sbio, cbio);

#ifdef NET_LOGIN
   if(netread(sbio, &code, &nlogin, sizeof(nlogin)) || (code != NET_LOGIN)) return -1;

   printf("Local signature length: %u\n", strlen(conf.signature));
   for(i = 0, code = NET_OK; i < strlen(conf.signature); i++) {
      printf("%02u: L%x R%x\n", i + 1, conf.signature[i], nlogin.signature[i]);
      if(conf.signature[i] == nlogin.signature[i]) continue;
      printf("ERROR\n");
      code = NET_NO;
   }

   if(netwrite(sbio, code, NULL, 0)) return -1;

   if(code == NET_NO) {
      logme(LOGMSG_ERROR, "Authentication error");
      return -1;
   }
   logme(LOGMSG_DEBUG, "Authentication succeded");
#endif /* NET_LOGIN */

#ifdef NET_VERSION
   memset(&nversion, '\0', sizeof(nversion));
   strncpy(nversion.version, conf.version, sizeof(nversion.version) - 1);

   if(netwrite(sbio, NET_VERSION, &nversion, sizeof(nversion)) || netread(sbio, &code, NULL, 0) || (code != NET_OK)) {
      logme(LOGMSG_ERROR, "Error sending version (%s)", conf.version);
      return -1;
   }
   logme(LOGMSG_DEBUG, "Version sent (%s)", conf.version);
#endif /* NET_VERSION */

#ifdef NET_CONFIG
   if(netwrite(sbio, NET_CONFIG, NULL, 0)) return -1;
   while(1) {
      if(netread(sbio, &code, &nconfig, sizeof(nconfig)) == -1) return -1;
      if(code != NET_CONFIG) {
         if(code != NET_NO) return -1;
         break;
      }
      if(netreadfile(sbio, NEXTHOP_FILE, nconfig.filesize)) return -1;
      logme(LOGMSG_INFO, "Config received, reloading nexthop", nconfig.filename);
      if(system("killall -1 " PROGNAME)) {
         logme(LOGMSG_ERROR, "Error sending HUP signal");
         return -1;
      }
   }
#endif /* NET_CONFIG */

#ifdef NET_UPGRADE
   if(netwrite(sbio, NET_UPGRADE, NULL, 0)) return -1;
   while(1) {
      if(netread(sbio, &code, &nupgrade, sizeof(nupgrade)) == -1) return -1;
      if(code != NET_UPGRADE) {
         if(code != NET_NO) return -1;
         break;
      }
      if(netreadfile(sbio, UPGRADE_FILE, nupgrade.filesize)) return -1;
      wantupgrade = 1;
      logme(LOGMSG_INFO, "Upgrade received", nupgrade.filename);
   }
#endif /* NET_UPGRADE */

#ifdef NET_MONITOR
   memset(&nmonitor, '\0', sizeof(nmonitor));

   cmd = COMMAND_GETSTATUS;
   write(ifd[1], &cmd, sizeof(cmd));
   read(ifd[1], &l, sizeof(l));

   strncpy(nmonitor.status, (l.level == LOGMSG_STATUSOK) ? "OK" : "ERROR", sizeof(nmonitor.status) - 1);
   strncpy(nmonitor.desc, l.data, sizeof(nmonitor.desc) - 1);

   if(statvfs("/", &vfs) == -1) return -1;
   nmonitor.disk = (uint32_t)(((uint64_t)(vfs.f_bavail)) * 100 / vfs.f_blocks);
   if(nmonitor.disk > 100) nmonitor.disk = 100;

   getcpustat(&cpusum1, &cpuidle1);
   sleep(1);
   getcpustat(&cpusum2, &cpuidle2);
   nmonitor.cpu = (unsigned int)(((cpusum2 - cpuidle2) - (cpusum1 - cpuidle1)) * 100 / (cpusum2 - cpusum1));
   if(nmonitor.cpu > 100) nmonitor.cpu = 100;

   /* TODO qui bisogna calcolare i valori corretti */
   nmonitor.pcpu = 0;

   if(netwrite(sbio, NET_MONITOR, &nmonitor, sizeof(nmonitor))) return -1;

   if(netread(sbio, &code, NULL, 0) || (code != NET_OK)) {
      logme(LOGMSG_ERROR, "Error sending monitor information");
      return -1;
   }
   logme(LOGMSG_DEBUG, "Monitor information sent ([%s] %s)", nmonitor.status, nmonitor.desc);
#endif /* NET_MONITOR */

#ifdef NET_LOG
   cmd = COMMAND_GETLOG;
   write(ifd[1], &cmd, sizeof(cmd));

   while(1) {
      read(ifd[1], &l, sizeof(l));
      if(l.level == LOGMSG_EMPTY) break;

      memset(&nlog, '\0', sizeof(nlog));
      switch(l.level) {
         case LOGMSG_INFO:
            nlog.level = 0x00;
            break;
         case LOGMSG_ERROR:
            nlog.level = 0x01;
            break;
         case LOGMSG_DEBUG:
            nlog.level = 0x02;
            break;
      }
      gmtime_r((time_t *)&l.ts, &t);
      nlog.t.tm_sec = t.tm_sec;
      nlog.t.tm_min = t.tm_min;
      nlog.t.tm_hour = t.tm_hour;
      nlog.t.tm_mday = t.tm_mday;
      nlog.t.tm_mon = t.tm_mon + 1;
      nlog.t.tm_year = t.tm_year + 1900;
      nlog.t.tm_wday = t.tm_wday;
      nlog.t.tm_yday = t.tm_yday;
      nlog.t.tm_isdst = t.tm_isdst;
      strncpy(nlog.desc, l.data, sizeof(nlog.desc) - 1);

      if(netwrite(sbio, NET_LOG, &nlog, sizeof(nlog))) {
         logme(LOGMSG_ERROR, "Error sending logs");
         return -1;
      }
   }
   logme(LOGMSG_DEBUG, "Logs sent");
#endif /* NET_LOG */

#ifdef NET_BYE
   if(netwrite(sbio, NET_BYE, NULL, 0)) {
      logme(LOGMSG_ERROR, "Error sending bye");
      return -1;
   } 
   logme(LOGMSG_DEBUG, "Bye sent");
#endif /* NET_BYE */

   if(wantupgrade) {
      close(cfd);
      logme(LOGMSG_INFO, "Upgrading..");
      chmod(UPGRADE_FILE, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
      system(UPGRADE_FILE);
   }

   return 0;
}

int getcpustat(uint64_t *cpusum, uint64_t *cpuidle)
{
   FILE *fp;
   char line[1024], *lp;
   uint64_t cputmp = 0;
   int pos = 0;

   *cpusum = 0;
   *cpuidle = 0;

   if(!(fp = fopen("/proc/stat", "r"))) return -1;
   fgets(line, sizeof(line), fp);
   fclose(fp);
   if(strncmp(line, "cpu ", 4)) return -1;

   for(lp = line; !isdigit(lp[0]) && lp[0]; lp++);
   while(lp[0]) {
      if(sscanf(lp, "%llu", &cputmp)) {
         *cpusum += cputmp;
         if(pos++ == 3) *cpuidle = cputmp;
      }
      while(isdigit(lp[0])) lp++;
      while(isspace(lp[0])) lp++;
   }

   return 0;
}
