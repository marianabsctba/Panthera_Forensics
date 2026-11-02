#!/bin/bash
# Prepara o ambiente Linux dedicado. Roda so na distribuicao panthera-forense.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates software-properties-common tshark >/dev/null
add-apt-repository -y ppa:oisf/suricata-stable >/dev/null
add-apt-repository -y ppa:gift/stable >/dev/null
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' > /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg
apt-get update -qq
apt-get install -y -qq suricata zeek-lts plaso-tools python3-libvshadow python3-libewf python3-pytsk3 >/dev/null
suricata-update --no-test >/dev/null 2>&1
test -x /opt/zeek/bin/zeek
test -s /var/lib/suricata/rules/suricata.rules
tshark --version >/dev/null
log2timeline.py --version >/dev/null 2>&1
python3 -c "import pyewf, pytsk3, pyvshadow"
