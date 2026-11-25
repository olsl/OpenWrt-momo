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

function split_alpn(v) {
	if (v == null || v === '' || v == 'default') return null;
	let parts = split(v, ',');
	let out = [];
	for (let i = 0; i < length(parts); i++) {
		let p = trim(parts[i]);
		if (p !== '') push(out, p);
	}
	return length(out) ? out : null;
}

// TLS built from certificate fields; used by both TLS-capable tunnels and
// protocols that always require a certificate (naive/hysteria/tuic/hysteria2).
function cert_tls(n) {
	let tls = { enabled: true };
	if (gb(n, 'tls_use_pem')) {
		tls.certificate = split_lines(g(n, 'tls_certificate'));
		tls.key = split_lines(g(n, 'tls_key'));
	} else {
		tls.certificate_path = g(n, 'tls_certificateFile');
		tls.key_path = g(n, 'tls_keyFile');
	}
	let alpn = split_alpn(g(n, 'alpn', 'default'));
	if (alpn) tls.alpn = alpn;
	return clean(tls);
}

function tls_config(n) {
	if (!gb(n, 'tls')) return null;
	let tls = cert_tls(n);

	if (gb(n, 'reality')) {
		delete tls.certificate_path;
		delete tls.key_path;
		delete tls.certificate;
		delete tls.key;
		let server = g(n, 'reality_handshake_server', 'google.com');
		tls.server_name = server;
		tls.reality = {
			enabled: true,
			private_key: g(n, 'reality_private_key'),
			short_id: [ g(n, 'reality_shortId') ],
			handshake: {
				server: server,
				server_port: to_int(g(n, 'reality_handshake_server_port', '443'), 443)
			}
		};
	}

	if (gb(n, 'ech')) {
		tls.ech = { enabled: true, key: split_lines(g(n, 'ech_key')) };
	}

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

function hy2_realm_config(n) {
	if (!gb(n, 'hysteria2_realms')) return null;
	let url = g(n, 'hysteria2_realm_url');
	if (url == null || url === '') return null;
	let realm = {
		server_url: url,
		stun_servers: gl(n, 'hysteria2_realm_stun'),
		stun_domain_resolver: 'direct'
	};
	if (gb(n, 'hysteria2_realm_upnp')) realm.port_mapping = { enabled: true };
	return clean(realm);
}

function build_user(us, protocol, node) {
	let u = {};
	if (protocol == 'mixed' || protocol == 'socks' || protocol == 'http' || protocol == 'naive') {
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

function collect_users(node, user_map) {
	let users = [];
	let user_ids = gl(node, 'users');
	for (let i = 0; i < length(user_ids); i++) {
		let us = user_map[user_ids[i]];
		if (us != null) push(users, build_user(us, g(node, 'protocol', 'mixed'), node));
	}
	return length(users) ? users : null;
}

function build_endpoint_wg(node, users, id) {
	return clean({
		type: 'wireguard',
		tag: 'inbound',
		listen_port: to_int(g(node, 'port'), null),
		system: gb(node, 'wireguard_system_interface'),
		name: 'sbwg_' + id,
		mtu: to_int(g(node, 'wireguard_mtu', '1408'), 1408),
		address: gl(node, 'wireguard_local_address'),
		private_key: g(node, 'wireguard_private_key'),
		peers: users
	});
}

function build_inbound(node, users) {
	let protocol = g(node, 'protocol', 'mixed');
	let port = to_int(g(node, 'port'), null);
	let inbound = {
		type: protocol,
		tag: 'inbound',
		listen: '::',
		listen_port: port
	};

	let tls = tls_config(node);
	let cert = cert_tls(node);
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

	} else if (protocol == 'naive') {
		extra.users = users;
		extra.tls = cert;

	} else if (protocol == 'hysteria') {
		let up = g(node, 'hysteria_up_mbps', '100');
		let down = g(node, 'hysteria_down_mbps', '100');
		extra.up = up + ' Mbps';
		extra.down = down + ' Mbps';
		extra.up_mbps = to_int(up, null);
		extra.down_mbps = to_int(down, null);
		extra.obfs = g(node, 'hysteria_obfs');
		extra.users = users;
		extra.stream_receive_window = to_int(g(node, 'hysteria_recv_window_conn'), null);
		extra.connection_receive_window = to_int(g(node, 'hysteria_recv_window_client'), null);
		extra.max_concurrent_streams = to_int(g(node, 'hysteria_max_conn_client', '1024'), 1024);
		extra.disable_path_mtu_discovery = gb(node, 'hysteria_disable_mtu_discovery');
		extra.tls = cert;

	} else if (protocol == 'tuic') {
		if (cert) {
			let tuic_alpn = split_alpn(g(node, 'tuic_alpn', 'default'));
			if (tuic_alpn) cert.alpn = tuic_alpn;
		}
		extra.users = users;
		extra.congestion_control = g(node, 'tuic_congestion_control', 'cubic');
		extra.zero_rtt_handshake = gb(node, 'tuic_zero_rtt_handshake');
		extra.heartbeat = (to_int(g(node, 'tuic_heartbeat', '3'), 3)) + 's';
		extra.tls = cert;

	} else if (protocol == 'hysteria2') {
		let ignore = gb(node, 'hysteria2_ignore_client_bandwidth');
		extra.up_mbps = ignore ? null : to_int(g(node, 'hysteria2_up_mbps'), null);
		extra.down_mbps = ignore ? null : to_int(g(node, 'hysteria2_down_mbps'), null);
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
		extra.ignore_client_bandwidth = ignore;
		extra.tls = cert;
		extra.realm = hy2_realm_config(node);

	} else if (protocol == 'snell') {
		extra.users = users;
		extra.version = to_int(g(node, 'snell_version', '5'), 5);
		extra.psk = g(node, 'snell_psk');
		if (extra.version == 5) {
			extra.obfs_mode = g(node, 'snell_obfs_mode', 'none');
		} else {
			extra.mode = g(node, 'snell_mode', 'default');
		}
	}

	for (let k in keys(extra)) inbound[k] = extra[k];
	return clean(inbound);
}

function build_outbound(n) {
	let mode = g(n, 'outbound_node', '');
	if (mode == null || mode === '') return null;

	if (mode == '_iface') {
		return clean({
			type: 'direct',
			tag: 'outbound',
			bind_interface: g(n, 'outbound_node_iface'),
			routing_mark: 255
		});
	}

	if (mode == '_socks' || mode == '_http') {
		let ob = {
			type: mode == '_socks' ? 'socks' : 'http',
			tag: 'outbound',
			server: g(n, 'outbound_node_address'),
			server_port: to_int(g(n, 'outbound_node_port'), null)
		};
		let user = g(n, 'outbound_node_username');
		let pass = g(n, 'outbound_node_password');
		if (user) ob.username = user;
		if (pass) ob.password = pass;
		return clean(ob);
	}

	return null;
}

function assemble_config(node, inbound, endpoint) {
	let logcfg = gb(node, 'log')
		? { level: g(node, 'loglevel', 'info'), timestamp: true, disabled: false }
		: { disabled: true };

	let chain = build_outbound(node);
	let outbounds = [];
	if (chain) push(outbounds, chain);
	push(outbounds, { type: 'direct', tag: 'direct' });

	let private_rule = gb(node, 'accept_lan')
		? { ip_is_private: true, action: 'route', outbound: 'direct' }
		: { ip_is_private: true, action: 'reject' };
	let route = { rules: [ private_rule ] };
	if (chain) route.final = 'outbound';

	let config = { log: logcfg, outbounds: outbounds, route: route };
	if (endpoint != null) {
		config.endpoints = [ endpoint ];
		config.inbounds = [];
	} else {
		config.inbounds = [ inbound ];
	}
	return config;
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
	let protocol = g(node, 'protocol', 'mixed');
	let config;
	let inbound = null;
	let endpoint = null;

	if (gb(node, 'custom')) {
		let raw = g(node, 'custom_config', '');
		if (raw == null || raw === '') return;
		config = json(raw);
	} else {
		let users = collect_users(node, user_map);
		if (protocol == 'wireguard') {
			endpoint = build_endpoint_wg(node, users, id);
		} else {
			inbound = build_inbound(node, users);
		}
		config = assemble_config(node, inbound, endpoint);
	}

	let config_file = TMP_DIR + '/' + id + '.json';
	writefile(config_file, clean(config));

	push(manifest, {
		id: id,
		port: inbound != null ? inbound.listen_port : (endpoint != null ? endpoint.listen_port : to_int(g(node, 'port'), null)),
		protocol: protocol,
		remarks: g(node, 'remarks', id),
		log: gb(node, 'log')
	});
});

writefile(TMP_DIR + '/manifest.json', manifest);
