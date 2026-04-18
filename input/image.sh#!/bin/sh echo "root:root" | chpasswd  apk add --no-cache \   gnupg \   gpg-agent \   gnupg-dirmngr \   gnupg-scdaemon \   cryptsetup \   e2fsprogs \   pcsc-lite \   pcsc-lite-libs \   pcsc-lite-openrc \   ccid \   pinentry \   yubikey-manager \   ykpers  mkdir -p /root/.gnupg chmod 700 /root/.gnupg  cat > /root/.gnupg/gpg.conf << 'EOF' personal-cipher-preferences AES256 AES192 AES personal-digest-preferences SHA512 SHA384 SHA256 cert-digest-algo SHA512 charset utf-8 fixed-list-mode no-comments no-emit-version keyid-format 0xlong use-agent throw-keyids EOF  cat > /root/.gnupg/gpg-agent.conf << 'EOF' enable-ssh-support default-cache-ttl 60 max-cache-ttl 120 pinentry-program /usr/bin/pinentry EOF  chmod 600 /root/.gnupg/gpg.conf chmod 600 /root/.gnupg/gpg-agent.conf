#!/bin/sh
echo "root:root" | chpasswd

apk add --no-cache \
  gnupg \
  gpg-agent \
  gnupg-dirmngr \
  gnupg-scdaemon \
  cryptsetup \
  e2fsprogs \
  pcsc-lite \
  pcsc-lite-libs \
  pcsc-lite-openrc \
  ccid \
  pinentry \
  yubikey-manager \
  ykpers

mkdir -p /root/.gnupg
chmod 700 /root/.gnupg

cat > /root/.gnupg/gpg.conf << 'EOF'
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
cert-digest-algo SHA512
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
use-agent
throw-keyids
EOF

cat > /root/.gnupg/gpg-agent.conf << 'EOF'
enable-ssh-support
default-cache-ttl 60
max-cache-ttl 120
pinentry-program /usr/bin/pinentry
EOF

chmod 600 /root/.gnupg/gpg.conf
chmod 600 /root/.gnupg/gpg-agent.conf
