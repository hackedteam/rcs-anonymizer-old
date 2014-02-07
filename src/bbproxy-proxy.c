#define FOUND_COOKIE 0x00000001
#define FOUND_XFF    0x00000002
#define FOUND_XPV    0x00000004

#define PROTO_ERR     0x00000000
#define PROTO_OK      0x000F0001
#define PROTO_NO      0x000F0002
#define PROTO_LOGIN   0x000F0004
#define PROTO_VERSION 0x000F0008

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

int proxyhandler(BIO *cbio);

int proxyhandler(BIO *cbio)
{
   BIO *sbio = NULL;
   int cfd, sfd, len = 0, found = 0;
   fd_set rfds;
   char buf[1024];
   struct sockaddr_in caddr;

   sbio = BIO_new_connect(conf.nexthop);

   if(BIO_do_connect(sbio) != 1) {
      logme(LOGMSG_STATUSERROR, "Unable to connect to %s", conf.nexthop);

      return -1;
   }
   logme(LOGMSG_STATUSOK, "Running");
   logme(LOGMSG_DEBUG, "Connected to %s", conf.nexthop);
   sfd = BIO_get_fd(sbio, NULL);

   cfd = BIO_get_fd(cbio, NULL);
   len = sizeof(caddr);
   getpeername(cfd, (struct sockaddr *)&caddr, (socklen_t *)&len);

   for(len = 0; ; len = 0) {
      while(len < sizeof(buf)) {
         if(BIO_read(cbio, buf + len, 1) != 1) return -1;
         if(buf[len++] == '\n') break;
      }
      buf[--len] = '\0';
      if(len && (buf[len - 1] == '\r')) buf[len - 1] = '\0';
      if(!buf[0]) break;

      if(!strncasecmp(buf, "Cookie: ", strlen("Cookie: "))) found |= FOUND_COOKIE;
      if(!strncasecmp(buf, "X-Forwarded-For: ", strlen("X-Forwarded-For: "))) found |= FOUND_XFF;
      if(!strncasecmp(buf, "X-Proxy-Version: ", strlen("X-Proxy-Version: "))) found |= FOUND_XPV;
      if(BIO_printf(sbio, "%s\r\n", buf) <= 0) return -1;
   }

   if(!(found & FOUND_COOKIE)) logme(LOGMSG_DEBUG, "New session forwarded for %s", inet_ntoa(caddr.sin_addr));
   if(!(found & FOUND_XFF)) if(BIO_printf(sbio, "X-Forwarded-For: %s\r\n", inet_ntoa(caddr.sin_addr)) <= 0) return -1;
   if(!(found & FOUND_XPV)) if(BIO_printf(sbio, "X-Proxy-Version: %s\r\n", conf.version) <= 0) return -1;
   if(BIO_puts(sbio, "\r\n") <= 0) return -1;

   do {
      FD_ZERO(&rfds);
      FD_SET(sfd, &rfds);
      FD_SET(cfd, &rfds);
      if(select(((sfd > cfd) ? sfd : cfd) + 1, &rfds, NULL, NULL, NULL) == -1) return -1;

      if(FD_ISSET(sfd, &rfds)) {
         if((len = BIO_read(sbio, buf, sizeof(buf))) > 0) if(BIO_write(cbio, buf, len) <= 0) return -1;
      } else if(FD_ISSET(cfd, &rfds)) {
         if((len = BIO_read(cbio, buf, sizeof(buf))) > 0) if(BIO_write(sbio, buf, len) <= 0) return -1;
      }
   } while(len > 0);

   return 0;
}
