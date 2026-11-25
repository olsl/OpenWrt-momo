#!/bin/sh

# uninstall
if [ -x "/bin/opkg" ]; then
	opkg list-installed luci-i18n-momo-* | cut -d ' ' -f 1 | xargs opkg remove
	opkg remove luci-app-momo
	opkg remove momo
elif [ -x "/usr/bin/apk" ]; then
	apk list --installed --manifest luci-i18n-momo-* | cut -d ' ' -f 1 | xargs apk del
	apk del luci-app-momo
	apk del momo
fi
# remove config
# restore dnsmasq upstream added by momo before the momo config is gone
momo_section=$(uci -q get momo.mixin.dnsmasq_server_section)
[ -n "$momo_section" ] && {
	uci -q delete "$momo_section.server=127.0.0.1#5354"
	uci -q commit dhcp
	/etc/init.d/dnsmasq restart > /dev/null 2>&1
}
rm -f /etc/config/momo
# remove files
rm -rf /etc/momo
# remove log
rm -rf /var/log/momo
# remove temp
rm -rf /var/run/momo
# remove feed
if [ -x "/bin/opkg" ]; then
	if grep -q momo /etc/opkg/customfeeds.conf; then
		sed -i '/momo/d' /etc/opkg/customfeeds.conf
	fi
	wget -O "momo.pub" "https://momomomo.pages.dev/key-build.pub"
	opkg-key remove momo.pub
	rm -f momo.pub
elif [ -x "/usr/bin/apk" ]; then
	if grep -q momo /etc/apk/repositories.d/customfeeds.list; then
		sed -i '/momo/d' /etc/apk/repositories.d/customfeeds.list
	fi
	rm -f /etc/apk/keys/momo.pem
fi
