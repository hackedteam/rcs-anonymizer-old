#!/bin/sh

###
### BBProxy installer
###

echo -n "Installing bbproxy"

if [ `whoami` != "root" ]; then
   echo -e "\n[ERROR] You must be root"
   exit 1
fi

echo -n "."

if [ -x /etc/init.d/bbproxy ]; then
   /etc/init.d/bbproxy stop
elif [ -x /opt/bbproxy/init.d/bbproxy ]; then
   /opt/bbproxy/init.d/bbproxy stop
fi

echo -n "."

if fuser -s 80/tcp 443/tcp; then
   echo -e "\n[ERROR] The following processes must be terminated before installation"
   fuser -v 80/tcp 443/tcp
   exit 1
fi

if fuser -4 -s 80/tcp 443/tcp; then
   echo -e "\n[ERROR] The following processes must be terminated before installation"
   fuser -4 -v 80/tcp 443/tcp
   exit 1
fi

echo -n "."

if ! tail -n +70 "$0" | tar xz -C /opt/; then
   echo -e "\n[ERROR] Unable to extract the tarball"
   exit 1;
fi

echo -n "."

mkdir -p /opt/bbproxy/tmp/

if [ -d /etc/init.d ]; then
   cp /opt/bbproxy/init.d/bbproxy /etc/init.d/bbproxy
   chmod 0755 /etc/init.d/bbproxy
   
   if chkconfig --add bbproxy >/dev/null 2>&1; then true
   elif update-rc.d bbproxy defaults >/dev/null 2>&1; then true
   else echo -e "\n[WARNING] The distribution is not supported, you must run \"/etc/init.d/bbproxy start\" manually at boot"
   fi

   /etc/init.d/bbproxy start
else
   echo -e "\n[WARNING] The distribution is not supported, you must run \"/opt/bbproxy/init.d/bbproxy start\" manually at boot"

   /opt/bbproxy/init.d/bbproxy start
fi

echo "."

echo "Installation completed"

exit 0

#EOF
