![GitHub License](https://img.shields.io/github/license/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) ![GitHub Tag](https://img.shields.io/github/v/release/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nikkinikki-org/OpenWrt-momo/total?style=for-the-badge&logo=github) ![GitHub Repo stars](https://img.shields.io/github/stars/nikkinikki-org/OpenWrt-momo?style=for-the-badge&logo=github) [![Telegram](https://img.shields.io/badge/Telegram-gray?style=for-the-badge&logo=telegram)](https://t.me/nikkinikki_org)

中文 | [English](README.md)

# Momo

在 OpenWrt 上使用 sing-box 进行透明代理。

## 环境要求

- OpenWrt >= 24.10
- Linux Kernel >= 5.13
- firewall4

## 功能

- 透明代理 (Redirect/TPROXY/TUN, IPv4 和/或 IPv6)
- 访问控制（按用户/用户组/CGroup/IP/IP6/MAC 分流）
- 配置文件编辑器
- 定时重启

## 订阅转换与 DNS 链路

- 订阅下载落盘前由 `/etc/momo/scripts/sub_convert.sh`（jq）自动转换：
  - 注入 momo 三件套入站：`dns-in`（0.0.0.0:5354 direct）、`tproxy-in`（0.0.0.0:12345）、`tun-in`（momo-tun）。
  - 路由顶部插入 sniff 规则，原 inbound tag `in` 改指 `tun-in`。
  - DNS 规则在 A/AAAA→fakeip 之前插入国内关键词直连 `domestic-dns`。
  - 删除所有 outbound 的 `tls.ech`；`🔰 手动选择` 默认指向首个含 `Cloudflare` 且 `0.1倍率` 的节点，否则回退 `♻️ 自动选择`。
  - 幂等：已含三件套入站时只做 ECH/默认节点修正。
- 默认 DNS 链路：LAN 客户端 53 先交 dnsmasq，dnsmasq 在本机 loopback 转发到本地 `dns-in:5354`（fakeip/直连分流在这层完成）；包内不再把跨设备 53 直接 redirect 到绑定回环的入站。服务启停时自动绑定/还原 dnsmasq 上游 `127.0.0.1#5354`。
- 默认通路为 TUN（TCP/UDP），本机出站经 `momo-tun` 接管；Redirect/TPROXY 仍可在 LuCI 切换。

## 安装和更新

### A. 从软件源安装（推荐）

1. 添加源

```shell
# 只需运行一次
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/feed.sh | ash
```

2. 安装

```shell
# 你可以从 shell 执行命令安装或者从 LuCI 的`软件包`菜单安装
# for opkg
opkg install momo
opkg install luci-app-momo
opkg install luci-i18n-momo-zh-cn
# for apk
apk add momo
apk add luci-app-momo
apk add luci-i18n-momo-zh-cn
```

### B. 从发行版安装

```shell
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/install.sh | ash
```

## 卸载并重置

```shell
wget -O - https://github.com/nikkinikki-org/OpenWrt-momo/raw/refs/heads/main/uninstall.sh | ash
```

## 如何使用

查看 [Wiki](https://github.com/nikkinikki-org/OpenWrt-momo/wiki)

## 如何工作

1. 启动 sing-box。
2. 设置定时重启。
3. 从配置文件读取必要的参数。
4. 配置 IP 规则/路由。
5. 生成防火墙配置并应用。

注意上述步骤可能因配置而变动。

## 编译

```shell
# 添加源
echo "src-git momo https://github.com/nikkinikki-org/OpenWrt-momo.git;main" >> "feeds.conf.default"
# 更新并安装源
./scripts/feeds update -a
./scripts/feeds install -a
# 编译
make package/luci-app-momo/compile
```

编译结果可以在`bin/packages/your_architecture/momo`内找到。

## 依赖

- ca-bundle
- curl
- firewall4
- ip-full
- kmod-inet-diag
- kmod-nft-socket
- kmod-nft-tproxy
- kmod-tun
- sing-box >= 1.12

## 贡献者

[![贡献者](https://contrib.rocks/image?repo=nikkinikki-org/OpenWrt-momo)](https://github.com/nikkinikki-org/OpenWrt-momo/graphs/contributors)
