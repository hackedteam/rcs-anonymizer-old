#ifndef _BBPROXY_H
#define _BBPROXY_H 1

#define VERSION_DEFAULT     "undefined"
#define MANAGERPORT_DEFAULT "443"
#define PROXYPORT_DEFAULT   "80"

#ifndef PROGNAME
   #define PROGNAME "bbproxy"
#endif

#ifndef PREFIX
   #define PREFIX "/opt/bbproxy"
#endif

#define VERSION_FILE        PREFIX "/etc/version"
#define MANAGERPORT_FILE    PREFIX "/etc/managerport"
#define CERTIFICATE_FILE    PREFIX "/etc/certificate"
#define SIGNATURE_FILE      PREFIX "/etc/signature"
#define PROXYPORT_FILE      PREFIX "/etc/proxyport"
#define NEXTHOP_FILE        PREFIX "/etc/nexthop"
#define UPGRADE_FILE        PREFIX "/tmp/bbproxy-install"

#define _BSD_SOURCE 1
#define _XOPEN_SOURCE 1000

#define LOGMSG_EMPTY       0x00
#define LOGMSG_STATUSOK    0x01
#define LOGMSG_STATUSERROR 0x02
#define LOGMSG_ERROR       0x04
#define LOGMSG_INFO        0x08
#define LOGMSG_DEBUG       0x10

#define COMMAND_GETSTATUS 0x01
#define COMMAND_GETLOG    0x02

struct {
   char *version;
   int loglevel;
   char *managerport;
   char *certificate;
   char *signature;
   char *proxyport;
   char *nexthop;
} conf;

struct log {
   int level;
   unsigned int ts;
   char data[128];
} __attribute__((__packed__));

void logme(int level, char *format, ...);
int readconfig_str(char *filename, char **param);
int readconfig_int(char *filename, int *param);

#endif /* _BBPROXY_H */
