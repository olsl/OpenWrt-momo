#!/bin/sh
# ============================================================
# momo 订阅转换器 (Marvis 定制)
# inbounds : dns-in(0.0.0.0:5354 direct) / tproxy-in(0.0.0.0:12345) / tun-in(momo-tun)
# route    : 顶部插入 sniff 规则; 原 inbound tag "in" 改 "tun-in"
# dns      : 国内域名关键词直连 domestic-dns (置于 A/AAAA->fakeip 之前)
# ech      : 删除所有 outbound 的 tls.ech (机场 ECH 配置与 DNS 记录不匹配会导致节点全挂)
# default  : 🔰 手动选择 默认指向首个 Cloudflare 0.1倍率 节点(无则保持自动选择)
# 幂等: 已含 momo 三件套 inbounds 则跳过结构注入, 仅做 ech/default 修正
# 注意: 使用 contains/index 而非 test() (ophub jq 无 ONIGURUMA 正则库);
#       outbounds 修改必须用 map()/update 赋值, 禁止 [ .[] | ... ] 形式(会展开根对象)
# 用法: sub_convert.sh <input.json> [output.json]
# ============================================================
set -e
IN="$1"
OUT="${2:-$IN}"
[ -n "$IN" ] && [ -f "$IN" ] || { echo "sub_convert: input not found: $IN" >&2; exit 1; }

FIX='.outbounds |= map(if (.tls? and (.tls.ech? != null)) then del(.tls.ech) else . end)
| (.outbounds[] | select(.tag == "🔰 手动选择") | .default) = ([.outbounds[].tag | select(. != null) | select(contains("Cloudflare") and contains("0.1倍率"))][0] // "♻️ 自动选择")
| .route.rules = (if ([ .route.rules[] | select((.inbound? // null)=="dns-in" and .action=="hijack-dns")] | length) > 0 then .route.rules else
    ([ {"inbound":"dns-in","action":"sniff"}, {"inbound":"dns-in","port":5354,"action":"hijack-dns"} ] + .route.rules) end)'

if jq -e '(.inbounds | map(.tag)) as $t | ($t | index("dns-in")) and ($t | index("tproxy-in")) and ($t | index("tun-in"))' "$IN" >/dev/null 2>&1; then
    echo "sub_convert: inbounds already converted, refix only" >&2
    jq "$FIX" "$IN" > "${OUT}.tmp" && mv -f "${OUT}.tmp" "$OUT"
    echo "sub_convert: refixed -> $OUT" >&2
    exit 0
fi

jq '
    .inbounds = [
        {"tag":"dns-in","type":"direct","listen":"0.0.0.0","listen_port":5354},
        {"tag":"tproxy-in","type":"tproxy","listen":"0.0.0.0","listen_port":12345},
        {"tag":"tun-in","type":"tun","interface_name":"momo-tun","address":["172.18.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"strict_route":false,"stack":"system"}
    ]
    | .route.rules = (
        [
            {"inbound":"dns-in","action":"sniff"},
            {"inbound":"dns-in","port":5354,"action":"hijack-dns"},
            {"inbound":["tproxy-in","tun-in"],"action":"sniff"}
        ]
        + (.route.rules | map(if (.inbound? // null) == "in" then .inbound = "tun-in" else . end))
      )
    | .dns.rules = (.dns.rules | [ .[] | if (.query_type == ["A","AAAA"] and .server == "dns_fakeip") then
        {"domain_keyword":["baidu","qq.com","weibo","taobao","tmall","alipay","aliyun","jd.com","163.com","sina","bilibili"],"server":"domestic-dns"},
        .
      else . end ])
    | .outbounds |= map(if (.tls? and (.tls.ech? != null)) then del(.tls.ech) else . end)
    | (.outbounds[] | select(.tag == "🔰 手动选择") | .default) = ([.outbounds[].tag | select(. != null) | select(contains("Cloudflare") and contains("0.1倍率"))][0] // "♻️ 自动选择")
' "$IN" > "${OUT}.tmp" && mv -f "${OUT}.tmp" "$OUT"
echo "sub_convert: done -> $OUT" >&2
