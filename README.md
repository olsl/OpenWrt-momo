![GitHub License](https://img.shields.io/github/license/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) ![GitHub Tag](https://img.shields.io/github/v/release/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nikkinikki-org/OpenWrt-momo/total?style=for-the-badge&logo=github) ![GitHub Repo stars](https://img.shields.io/github/stars/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) [![Telegram](https://img.shields.io/badge/Telegram-gray?style=for-the-badge&logo=telegram)](https://t.me/nikkinikki_org)

English | [中文](README.zh.md)

# Momo

Transparent Proxy with sing-box on OpenWrt.

## Prerequisites

- OpenWrt >= 24.10
- Linux Kernel >= 5.13
- firewall4

## Feature

- Transparent Proxy (Redirect/TPROXY/TUN, IPv4 and/or IPv6)
- Access Control (by user/group/cgroup/IP/IP6/MAC)
- Profile Editor
- Scheduled Restart

## Subscription Conversion & DNS Path

- Before a subscription is persisted, `/etc/momo/scripts/sub_convert.sh` (jq) converts it:
  - Injects the momo inbound trio: `dns-in` (0.0.0.0:5354 direct), `tproxy-in` (0.0.0.0:12345), `tun-in` (momo-tun).
  - Inserts sniff rules at the top of route rules; rewrites the legacy `in` inbound tag to `tun-in`.
  - Inserts domestic-keyword rules pointing to `domestic-dns` before the A/AAAA→fakeip DNS rule.
  - Strips `tls.ech` from every outbound; sets `🔰 手动选择` default to the first `Cloudflare` + `0.1倍率` node, falling back to `♻️ 自动选择`.
  - Idempotent: when the trio already exists, only ECH/default-node are fixed.
- Default DNS path: LAN client port 53 goes to dnsmasq first; dnsmasq forwards over loopback to local `dns-in:5354` (fakeip/direct split happens there). Cross-device 53 is no longer redirected straight to a loopback-bound inbound. The dnsmasq upstream `127.0.0.1#5354` is added/removed automatically on service start/stop.
- Default transport is TUN (TCP/UDP); router-local traffic goes through `momo-tun`. Redirect/TPROXY remain selectable in LuCI.

## Install & Update

### A. Install From Feed (Recommended)

1. Add Feed

```shell
# only needs to be run once
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/feed.sh | ash
```

2. Install

```shell
# you can install from shell or `Software` menu in LuCI
# for opkg
opkg install momo
opkg install luci-app-momo
opkg install luci-i18n-momo-zh-cn
# for apk
apk add momo
apk add luci-app-momo
apk add luci-i18n-momo-zh-cn
```

### B. Install From Release

```shell
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/install.sh | ash
```

## Uninstall & Reset

```shell
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/uninstall.sh | ash
```

## How To Use

See [Wiki](https://github.com/nikkinikki-org/OpenWrt-momo/wiki)

## How does it work
 
1. Run sing-box.
2. Set scheduled restart.
3. Get neccesarry param from profile.
4. Set ip rule/route.
5. Generate firewall and apply it.

Note that the steps above may change base on config.

## Compilation

```shell
# add feed
echo "src-git momo https://github.com/nikkinikki-org/OpenWrt-momo.git;main" >> "feeds.conf.default"
# update & install feeds
./scripts/feeds update -a
./scripts/feeds install -a
# make package
make package/luci-app-momo/compile
```

The package files will be found under `bin/packages/your_architecture/momo`.

## Dependencies

- ca-bundle
- curl
- firewall4
- ip-full
- kmod-inet-diag
- kmod-nft-socket
- kmod-nft-tproxy
- kmod-tun
- sing-box >= 1.12

## Contributors

[![Contributors](https://contrib.rocks/image?repo=nikkinikki-org/OpenWrt-momo)](https://github.com/nikkinikki-org/OpenWrt-momo/graphs/contributors)
