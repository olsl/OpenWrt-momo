#!/usr/bin/ucode

'use strict';

import { writefile } from 'fs';
import { cursor } from 'uci';

const u = cursor();

const TMP_DIR = '/tmp/etc/momo_server';
const CONFIG = 'momo_server';

function g(sec, opt, def) {
	let v = u.get(CONFIG, sec['.name'], opt);
	if (v == null || v === '') return def == null ? null : def;
	return v;
}

function gb(sec, opt) {
	return g(sec, opt) == '1';
}

function gl(sec, opt) {
	let v = u.get(CONFIG, sec['.name'], opt);
	if (v == null) return [];
	if (type(v) == 'array') return v;
	return [v];
}

function arr(v) {
	if (v == null) return [];
	if (type(v) == 'array') return v;
	return [v];
}

function to_int(v, def) {
	if (v == null || v === '') return def == null ? null : def;
	let n = int(v);
	return n == null ? def : n;
}

function clean(obj) {
	if (type(obj) != 'object') return obj;
	for (let k in keys(obj)) {
		let v = obj[k];
		if (v == null || v === '' || (type(v) == 'array' && length(v) == 0)) {
			delete obj[k];
		} else if (type(v) == 'object') {
			obj[k] = clean(v);
		}
	}
	return obj;
}

function split_lines(str) {
	if (str == null || str === '') return [];
	let lines = split(str, '\n');
	let out = [];
	for (let i = 0; i < length(lines); i++) {
		let line = trim(split(lines[i], '\r')[0]);
		if (line !== '') push(out, line);
	}
	return out;
}

function tls_config(n) {
	if (!gb(n, 'tls')) return null;
	let tls = { enabled: true };
	if (gb(n, 'reality')) {
		tls.server_name = g(n, 'reality_handshake_server', 'google.com');
		tls.reality = {
			enabled: true,
			private_key: g(n, 'reality_private_key'),
			short_id: [ g(n, 'reality_shortId') ],
			handshake: {
				server: g(n, 'reality_handshake_server', 'google.com'),
				server_port: to_int(g(n, 'reality_handshake_server_port', '443'), 443)
			}
		};
		return clean(tls);
	}
	if (gb(n, 'tls_use_pem')) {
		tls.certificate = split_lines(g(n, 'tls_certificate'));
		tls.key = split_lines(g(n, 'tls_key'));
	} else {
		tls.certificate_path = g(n, 'tls_certificateFile');
		tls.key_path = g(n, 'tls_keyFile');
	}
	let alpn = g(n, 'alpn', 'default');
	if (alpn && alpn != 'default') tls.alpn = split(alpn, ',');
	return clean(tls);
}

function transport_config(n) {
	let t = g(n, 'transport', 'tcp');
	if (t == 'ws') {
		let headers = null;
		if (g(n, 'ws_host')) headers = { Host: g(n, 'ws_host') };
		return clean({ type: 'ws', path: g(n, 'ws_path', '/'), headers: headers,
			early_data_header_name: g(n, 'ws_earlyDataHeaderName', 'Sec-WebSocket-Protocol') });
	}
	if (t == 'http') {
		return clean({ type: 'http', host: gl(n, 'http_host'), path: g(n, 'http_path', '/') });
	}
	if (t == 'httpupgrade') {
		return clean({ type: 'httpupgrade', host: g(n, 'httpupgrade_host'), path: g(n, 'httpupgrade_path', '/') });
	}
	if (t == 'grpc') {
		return clean({ type: 'grpc', service_name: g(n, 'grpc_serviceName') });
	}
	if (t == 'quic') return { type: 'quic' };
	return null;
}

function mux_config(n) {
	if (!gb(n, 'mux')) return null;
	let m = { enabled: true, padding: false };
	if (gb(n, 'tcpbrutal')) {
		m.brutal = {
			enabled: true,
			up_mbps: to_int(g(n, 'tcpbrutal_up_mbps', '10'), 10),
			down_mbps: to_int(g(n, 'tcpbrutal_down_mbps', '50'), 50)
		};
	}
	return clean(m);
}

function build_user(us, protocol, node) {
	let u = {};
	if (protocol == 'mixed' || protocol == 'socks' || protocol == 'http' || protocol == 'naive' || protocol == 'masque') {
		u.username = us.username;
		u.password = us.password;
	} else if (protocol == 'shadowsocks' || protocol == 'trojan' || protocol == 'hysteria2' || protocol == 'anytls') {
		u.name = us.username;
		u.password = us.password;
	} else if (protocol == 'vmess') {
		u.name = us.username;
		u.uuid = us.uuid;
		u.alterId = 0;
	} else if (protocol == 'vless') {
		u.name = us.username;
		u.uuid = us.uuid;
		u.flow = g(node, 'flow');
	} else if (protocol == 'hysteria') {
		u.name = us.username;
		u.auth_str = us.password;
	} else if (protocol == 'tuic') {
		u.name = us.username;
		u.password = us.password;
		u.uuid = us.uuid;
	} else if (protocol == 'wireguard') {
		u.public_key = us.wireguard_public_key;
		u.pre_shared_key = us.wireguard_pre_shared_key;
		u.allowed_ips = arr(us.allowed_ips);
		u.persistent_keepalive_interval = 0;
	} else if (protocol == 'snell') {
		u.name = us.username;
		u.userkey = us.password;
	}
	return clean(u);
}

function build_inbound(node, user_map) {
	let protocol = g(node, 'protocol', 'mixed');
	let port = to_int(g(node, 'port'), null);
	let inbound = {
		type: protocol,
		tag: 'inbound',
		listen: '::',
		listen_port: port
	};

	// attached users
	let users = [];
	let user_ids = gl(node, 'users');
	for (let i = 0; i < length(user_ids); i++) {
		let us = user_map[user_ids[i]];
		if (us != null) push(users, build_user(us, protocol, node));
	}
	if (length(users) == 0) users = null;

	let tls = tls_config(node);
	let transport = transport_config(node);
	let mux = mux_config(node);
	let extra = {};

	if (protocol == 'direct') {
		extra.network = g(node, 'd_protocol');
		extra.override_address = g(node, 'd_address');
		extra.override_port = to_int(g(node, 'd_port'), null);
	} else if (protocol == 'mixed') {
		extra.users = users;
		extra.set_system_proxy = false;
	} else if (protocol == 'socks') {
		extra.users = users;
	} else if (protocol == 'http') {
		extra.users = users;
		extra.tls = tls;
	} else if (protocol == 'shadowsocks') {
		extra.method = g(node, 'ss_method', 'aes-128-gcm');
		extra.password = g(node, 'ss_password');
		extra.users = users;
		extra.multiplex = mux;
	} else if (protocol == 'vmess' || protocol == 'vless' || protocol == 'trojan') {
		extra.users = users;
		extra.tls = tls;
		extra.multiplex = mux;
		extra.transport = transport;
	} else if (protocol == 'anytls') {
		extra.users = users;
		extra.tls = tls;
	} else if (protocol == 'hysteria2') {
		extra.up_mbps = gb(node, 'hysteria2_ignore_client_bandwidth') ? null : to_int(g(node, 'hysteria2_up_mbps'), null);
		extra.down_mbps = gb(node, 'hysteria2_ignore_client_bandwidth') ? null : to_int(g(node, 'hysteria2_down_mbps'), null);
		let obfs_type = g(node, 'hysteria2_obfs_type', '');
		if (obfs_type && obfs_type != '') {
			let obfs = { type: obfs_type, password: g(node, 'hysteria2_obfs_password') };
			if (obfs_type == 'gecko') {
				obfs.min_packet_size = to_int(g(node, 'hysteria2_obfs_MinPacketSize', '512'), 512);
				obfs.max_packet_size = to_int(g(node, 'hysteria2_obfs_MaxPacketSize', '1200'), 1200);
			}
			extra.obfs = clean(obfs);
		}
		extra.users = users;
		extra.ignore_client_bandwidth = gb(node, 'hysteria2_ignore_client_bandwidth');
		extra.tls = tls;
	} else if (protocol == 'wireguard') {
		extra.system_interface = gb(node, 'wireguard_system_interface');
		extra.mtu = to_int(g(node, 'wireguard_mtu', '1408'), 1408);
		extra.local_address = gl(node, 'wireguard_local_address');
		extra.private_key = g(node, 'wireguard_private_key');
		extra.users = users;
	} else if (protocol == 'snell') {
		extra.users = users;
		extra.version = g(node, 'snell_version', '5');
		extra.psk = g(node, 'snell_psk');
		if (extra.version == '5') extra.obfs_mode = g(node, 'snell_obfs_mode', 'none');
		else extra.mode = g(node, 'snell_mode', 'default');
	}

	for (let k in keys(extra)) inbound[k] = extra[k];
	return clean(inbound);
}

// collect users
const user_map = {};
u.foreach(CONFIG, 'user', (us) => {
	user_map[us['.name']] = {
		username: u.get(CONFIG, us['.name'], 'username'),
		password: u.get(CONFIG, us['.name'], 'password'),
		uuid: u.get(CONFIG, us['.name'], 'uuid'),
		wireguard_public_key: u.get(CONFIG, us['.name'], 'wireguard_public_key'),
		wireguard_pre_shared_key: u.get(CONFIG, us['.name'], 'wireguard_pre_shared_key'),
		allowed_ips: arr(u.get(CONFIG, us['.name'], 'allowed_ips'))
	};
});

const manifest = [];

u.foreach(CONFIG, 'server', (node) => {
	if (!gb(node, 'enable')) return;
	let id = node['.name'];
	let config;
	let inbound = null;

	if (gb(node, 'custom')) {
		let raw = g(node, 'custom_config', '');
		if (raw == null || raw === '') return;
		config = json(raw);
	} else {
		inbound = build_inbound(node, user_map);
		config = {
			log: gb(node, 'log') ? { level: g(node, 'loglevel', 'info'), timestamp: true, disabled: false } : { disabled: true },
			inbounds: [ inbound ],
			outbounds: [ { type: 'direct', tag: 'direct' } ]
		};
	}

	let config_file = TMP_DIR + '/' + id + '.json';
	writefile(config_file, clean(config));

	push(manifest, {
		id: id,
		port: inbound != null ? inbound.listen_port : to_int(g(node, 'port'), null),
		protocol: g(node, 'protocol', 'mixed'),
		remarks: g(node, 'remarks', id),
		log: gb(node, 'log')
	});
});

writefile(TMP_DIR + '/manifest.json', manifest);
