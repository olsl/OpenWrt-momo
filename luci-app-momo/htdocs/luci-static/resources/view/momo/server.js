'use strict';
'require form';
'require view';
'require uci';
'require poll';
'require tools.momo as momo';

const SS_METHODS = [
	'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
	'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
	'2022-blake3-chacha20-poly1305'
];

const PROTOCOLS = [
	['direct', 'Direct'],
	['mixed', 'Mixed'],
	['socks', 'Socks'],
	['http', 'HTTP'],
	['shadowsocks', 'Shadowsocks'],
	['vmess', 'VMess'],
	['vless', 'VLESS'],
	['trojan', 'Trojan'],
	['naive', 'Naive'],
	['anytls', 'AnyTLS'],
	['hysteria', 'Hysteria'],
	['tuic', 'TUIC'],
	['hysteria2', 'Hysteria2'],
	['wireguard', 'WireGuard'],
	['snell', 'Snell']
];

const TLS_PROTOCOLS = ['http', 'vmess', 'vless', 'trojan', 'anytls'];

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('momo_server'),
			uci.sections('momo_server', 'user')
		]);
	},

	render: function (data) {
		const userSections = data[1] || [];
		const userOptions = userSections.map(u => [u['.name'], u.username || u['.name']]);

		let m, s, srv, usr, o;

		m = new form.Map('momo_server', _('Server-Side'));

		// global
		s = m.section(form.NamedSection, 'global', 'global', _('Server-Side'));
		o = s.option(form.Flag, 'enable', _('Enable'));
		o.rmempty = false;

		// servers
		srv = m.section(form.GridSection, 'server', _('Servers Manager'));
		srv.addremove = true;
		srv.anonymous = true;
		srv.sortable = true;
		srv.rowcolors = true;
		srv.modaltitle = _('Edit Server');

		// ---- table columns ----
		o = srv.option(form.Flag, 'enable', _('Enable'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		o = srv.option(form.DummyValue, 'status', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function (section_id) {
			return E('span', { 'data-section': section_id, class: 'momo-srv-status' }, _('Collecting data...'));
		};

		o = srv.option(form.Value, 'remarks', _('Remarks'));

		o = srv.option(form.ListValue, 'protocol', _('Protocol'));
		PROTOCOLS.forEach(([v, t]) => o.value(v, t));

		o = srv.option(form.Value, 'port', _('Listen Port'));
		o.datatype = 'port';

		o = srv.option(form.Flag, 'log', _('Log'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		// ---- modal only: common ----
		o = srv.option(form.DynamicList, 'users', _('User'));
		o.modalonly = true;
		userOptions.forEach(([id, label]) => o.value(id, label));
		['mixed', 'socks', 'http', 'shadowsocks', 'vmess', 'vless', 'trojan', 'naive',
			'anytls', 'hysteria', 'tuic', 'hysteria2', 'wireguard', 'snell']
			.forEach(p => o.depends('protocol', p));

		o = srv.option(form.Flag, 'custom', _('Use Custom Config'));
		o.modalonly = true;
		o = srv.option(form.TextValue, 'custom_config', _('Custom Config') + ' (JSON)');
		o.rows = 10;
		o.wrap = 'off';
		o.modalonly = true;
		o.depends('custom', '1');

		// ---- shadowsocks ----
		o = srv.option(form.ListValue, 'ss_method', _('Encrypt Method'));
		o.modalonly = true;
		SS_METHODS.forEach(v => o.value(v));
		o.depends('protocol', 'shadowsocks');
		o = srv.option(form.Value, 'ss_password', _('Password'));
		o.modalonly = true;
		o.depends('protocol', 'shadowsocks');

		// ---- vless ----
		o = srv.option(form.ListValue, 'flow', _('Flow'));
		o.modalonly = true;
		o.value('', _('Disable'));
		o.value('xtls-rprx-vision');
		o.depends({ protocol: 'vless', tls: '1' });
		o = srv.option(form.Value, 'decryption', _('Encrypt Method'));
		o.modalonly = true;
		o.default = 'none';
		o.depends('protocol', 'vless');

		// ---- direct ----
		o = srv.option(form.ListValue, 'd_protocol', _('Destination protocol'));
		o.modalonly = true;
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');
		o.value('tcp,udp', 'TCP,UDP');
		o.depends('protocol', 'direct');
		o = srv.option(form.Value, 'd_address', _('Destination address'));
		o.modalonly = true;
		o.depends('protocol', 'direct');
		o = srv.option(form.Value, 'd_port', _('Destination port'));
		o.modalonly = true;
		o.datatype = 'port';
		o.depends('protocol', 'direct');

		// ---- TLS ----
		o = srv.option(form.Flag, 'tls', _('TLS'));
		o.modalonly = true;
		TLS_PROTOCOLS.forEach(p => o.depends('protocol', p));

		o = srv.option(form.Flag, 'reality', _('REALITY'));
		o.modalonly = true;
		o.depends({ tls: '1' });
		o = srv.option(form.Value, 'reality_private_key', _('Private Key'));
		o.modalonly = true;
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_shortId', _('Short Id'));
		o.modalonly = true;
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_handshake_server', _('Handshake Server'));
		o.modalonly = true;
		o.default = 'google.com';
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_handshake_server_port', _('Handshake Server Port'));
		o.modalonly = true;
		o.datatype = 'port';
		o.default = '443';
		o.depends('reality', '1');

		o = srv.option(form.ListValue, 'alpn', _('ALPN'));
		o.modalonly = true;
		o.default = 'default';
		o.value('default', _('Default'));
		['h3', 'h2', 'h3,h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1'].forEach(v => o.value(v));
		o.depends({ tls: '1', reality: '0' });
		o.depends('protocol', 'hysteria');

		o = srv.option(form.Flag, 'tls_use_pem', _('Use PEM'),
			_('Use certificate and private key PEM content.'));
		o.modalonly = true;
		o.depends({ tls: '1', reality: '0' });
		['naive', 'hysteria', 'tuic', 'hysteria2'].forEach(p => o.depends('protocol', p));

		o = srv.option(form.Value, 'tls_certificateFile', _('Path to the certificate file'));
		o.modalonly = true;
		o.depends({ tls: '1', reality: '0', tls_use_pem: '0' });
		['naive', 'hysteria', 'tuic', 'hysteria2'].forEach(p =>
			o.depends({ protocol: p, tls_use_pem: '0' }));
		o = srv.option(form.Value, 'tls_keyFile', _('Path to the private key file'));
		o.modalonly = true;
		o.depends({ tls: '1', reality: '0', tls_use_pem: '0' });
		['naive', 'hysteria', 'tuic', 'hysteria2'].forEach(p =>
			o.depends({ protocol: p, tls_use_pem: '0' }));

		o = srv.option(form.TextValue, 'tls_certificate', _('TLS Certificate (PEM)'));
		o.rows = 5;
		o.wrap = 'off';
		o.modalonly = true;
		o.depends('tls_use_pem', '1');
		o = srv.option(form.TextValue, 'tls_key', _('TLS Private Key (PEM)'));
		o.rows = 5;
		o.wrap = 'off';
		o.modalonly = true;
		o.depends('tls_use_pem', '1');

		o = srv.option(form.Flag, 'ech', _('ECH'));
		o.modalonly = true;
		o.depends({ tls: '1', reality: '0' });
		['naive', 'hysteria', 'tuic', 'hysteria2'].forEach(p => o.depends('protocol', p));
		o = srv.option(form.TextValue, 'ech_key', _('ECH Key'));
		o.rows = 5;
		o.wrap = 'off';
		o.modalonly = true;
		o.depends('ech', '1');

		// ---- transport ----
		o = srv.option(form.ListValue, 'transport', _('Transport'));
		o.modalonly = true;
		o.value('tcp', 'TCP');
		o.value('http', 'HTTP');
		o.value('ws', 'WebSocket');
		o.value('httpupgrade', 'HTTPUpgrade');
		o.value('quic', 'QUIC');
		o.value('grpc', 'gRPC');
		['shadowsocks', 'vmess', 'vless', 'trojan'].forEach(p => o.depends('protocol', p));

		o = srv.option(form.DynamicList, 'http_host', _('HTTP Host'));
		o.modalonly = true;
		o.depends('transport', 'http');
		o = srv.option(form.Value, 'http_path', _('HTTP Path'));
		o.modalonly = true;
		o.depends('transport', 'http');

		o = srv.option(form.Value, 'ws_host', _('WebSocket Host'));
		o.modalonly = true;
		o.depends('transport', 'ws');
		o = srv.option(form.Value, 'ws_path', _('WebSocket Path'));
		o.modalonly = true;
		o.depends('transport', 'ws');
		o = srv.option(form.Value, 'ws_earlyDataHeaderName', _('Early data header name'));
		o.modalonly = true;
		o.placeholder = 'Sec-WebSocket-Protocol';
		o.depends('transport', 'ws');

		o = srv.option(form.Value, 'httpupgrade_host', _('HTTPUpgrade Host'));
		o.modalonly = true;
		o.depends('transport', 'httpupgrade');
		o = srv.option(form.Value, 'httpupgrade_path', _('HTTPUpgrade Path'));
		o.modalonly = true;
		o.depends('transport', 'httpupgrade');

		o = srv.option(form.Value, 'grpc_serviceName', 'ServiceName');
		o.modalonly = true;
		o.depends('transport', 'grpc');

		// ---- mux ----
		o = srv.option(form.Flag, 'mux', _('Mux'));
		o.modalonly = true;
		['vmess', 'vless', 'shadowsocks', 'trojan'].forEach(p => o.depends('protocol', p));
		o = srv.option(form.Flag, 'tcpbrutal', _('TCP Brutal'));
		o.modalonly = true;
		o.depends('mux', '1');
		o = srv.option(form.Value, 'tcpbrutal_up_mbps', _('Max upload Mbps'));
		o.modalonly = true;
		o.default = '10';
		o.depends('tcpbrutal', '1');
		o = srv.option(form.Value, 'tcpbrutal_down_mbps', _('Max download Mbps'));
		o.modalonly = true;
		o.default = '50';
		o.depends('tcpbrutal', '1');

		// ---- hysteria v1 ----
		o = srv.option(form.Value, 'hysteria_obfs', _('Obfs Password'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Value, 'hysteria_up_mbps', _('Max upload Mbps'));
		o.modalonly = true;
		o.default = '100';
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Value, 'hysteria_down_mbps', _('Max download Mbps'));
		o.modalonly = true;
		o.default = '100';
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Value, 'hysteria_recv_window_client', _('QUIC connection receive window'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Value, 'hysteria_max_conn_client', _('QUIC concurrent bidirectional streams'));
		o.modalonly = true;
		o.default = '1024';
		o.depends('protocol', 'hysteria');
		o = srv.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable MTU detection'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria');

		// ---- tuic ----
		o = srv.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'));
		o.modalonly = true;
		o.default = 'cubic';
		o.value('bbr', 'BBR');
		o.value('cubic', 'CUBIC');
		o.value('new_reno', 'New Reno');
		o.depends('protocol', 'tuic');
		o = srv.option(form.Flag, 'tuic_zero_rtt_handshake', _('Enable 0-RTT QUIC handshake'));
		o.modalonly = true;
		o.depends('protocol', 'tuic');
		o = srv.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval (second)'));
		o.modalonly = true;
		o.datatype = 'uinteger';
		o.default = '3';
		o.depends('protocol', 'tuic');
		o = srv.option(form.ListValue, 'tuic_alpn', _('QUIC TLS ALPN'));
		o.modalonly = true;
		o.default = 'default';
		o.value('default', _('Default'));
		['h3', 'h2', 'h3,h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1', 'spdy/3.1', 'h3,spdy/3.1']
			.forEach(v => o.value(v));
		o.depends('protocol', 'tuic');

		// ---- hysteria2 ----
		o = srv.option(form.Flag, 'hysteria2_realms', _('Realms'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Value, 'hysteria2_realm_url', _('Realm URL'),
			_('Example: realm://public@realm.hy2.io/your-realm-name'));
		o.modalonly = true;
		o.depends('hysteria2_realms', '1');
		o = srv.option(form.DynamicList, 'hysteria2_realm_stun', _('Realm STUN'));
		o.modalonly = true;
		o.default = ['stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478'];
		o.depends('hysteria2_realms', '1');
		o = srv.option(form.Flag, 'hysteria2_realm_upnp', _('Enable UPnP/NAT-PMP'),
			_('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
		o.modalonly = true;
		o.depends('hysteria2_realms', '1');

		o = srv.option(form.ListValue, 'hysteria2_obfs_type', _('Obfs Type'));
		o.modalonly = true;
		o.value('', _('Disable'));
		o.value('salamander');
		o.value('gecko');
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Value, 'hysteria2_obfs_password', _('Obfs Password'));
		o.modalonly = true;
		o.depends('hysteria2_obfs_type', 'salamander');
		o.depends('hysteria2_obfs_type', 'gecko');
		o = srv.option(form.Value, 'hysteria2_obfs_MinPacketSize', _('Gecko Packet Size (min)'));
		o.modalonly = true;
		o.datatype = 'uinteger';
		o.default = '512';
		o.depends('hysteria2_obfs_type', 'gecko');
		o = srv.option(form.Value, 'hysteria2_obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
		o.modalonly = true;
		o.datatype = 'uinteger';
		o.default = '1200';
		o.depends('hysteria2_obfs_type', 'gecko');
		o = srv.option(form.Flag, 'hysteria2_ignore_client_bandwidth', _('Client BBR Flow Control'));
		o.modalonly = true;
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
		o.modalonly = true;
		o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: '0' });
		o = srv.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
		o.modalonly = true;
		o.depends({ protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: '0' });

		// ---- wireguard ----
		o = srv.option(form.Flag, 'wireguard_system_interface', _('System interface'));
		o.modalonly = true;
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Value, 'wireguard_mtu', 'MTU');
		o.modalonly = true;
		o.default = '1408';
		o.depends('protocol', 'wireguard');
		o = srv.option(form.DynamicList, 'wireguard_local_address', _('Local Address'));
		o.modalonly = true;
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Value, 'wireguard_private_key', _('Private Key'));
		o.modalonly = true;
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Value, 'wireguard_public_key', _('Public Key'));
		o.modalonly = true;
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Button, 'gen_wg_key', _('Generate key'));
		o.modalonly = true;
		o.depends('protocol', 'wireguard');
		o.inputtitle = _('Generate');
		o.inputstyle = 'positive';
		o.onclick = function (ev, section_id) {
			const self = this;
			return momo.genWgKeypair().then((res) => {
				if (!res || !res.private_key) return;
				const priv = self.section.getOption('wireguard_private_key');
				const pub = self.section.getOption('wireguard_public_key');
				if (priv) priv.getUIElement(section_id).setValue(res.private_key);
				if (pub) pub.getUIElement(section_id).setValue(res.public_key);
			});
		};

		// ---- snell ----
		o = srv.option(form.ListValue, 'snell_version', _('Version'));
		o.modalonly = true;
		o.value('5');
		o.value('6');
		o.depends('protocol', 'snell');
		o = srv.option(form.Value, 'snell_psk', _('Pre shared key'));
		o.modalonly = true;
		o.depends('protocol', 'snell');
		o = srv.option(form.ListValue, 'snell_obfs_mode', _('Obfs'));
		o.modalonly = true;
		o.value('none');
		o.value('http');
		o.depends({ protocol: 'snell', snell_version: '5' });
		o = srv.option(form.ListValue, 'snell_mode', _('Mode'));
		o.modalonly = true;
		o.value('default');
		o.value('unshaped');
		o.value('unsafe-raw');
		o.depends({ protocol: 'snell', snell_version: '6' });

		// ---- chained outbound node ----
	o = srv.option(form.ListValue, 'outbound_node', _('Outbound Node'));
	o.modalonly = true;
	o.value('', _('Close'));
	o.value('_socks', _('Custom Socks'));
	o.value('_http', _('Custom HTTP'));
	o.value('_iface', _('Custom Interface'));

	o = srv.option(form.Value, 'outbound_node_address', _('Address (Support Domain Name)'));
	o.modalonly = true;
	o.depends('outbound_node', '_socks');
	o.depends('outbound_node', '_http');
	o = srv.option(form.Value, 'outbound_node_port', _('Port'));
	o.modalonly = true;
	o.datatype = 'port';
	o.depends('outbound_node', '_socks');
	o.depends('outbound_node', '_http');
	o = srv.option(form.Value, 'outbound_node_username', _('Username'));
	o.modalonly = true;
	o.depends('outbound_node', '_socks');
	o.depends('outbound_node', '_http');
	o = srv.option(form.Value, 'outbound_node_password', _('Password'));
	o.modalonly = true;
	o.password = true;
	o.depends('outbound_node', '_socks');
	o.depends('outbound_node', '_http');
	o = srv.option(form.Value, 'outbound_node_iface', _('Interface'));
	o.modalonly = true;
	o.depends('outbound_node', '_iface');

	// ---- firewall / log ----
		o = srv.option(form.Flag, 'firewall_allow', _('Firewall Allow'));
		o.modalonly = true;
		o = srv.option(form.Value, 'firewall_allow_src', _('Source zone'));
		o.modalonly = true;
		o.default = 'wan';
		o.depends('firewall_allow', '1');
		o = srv.option(form.Flag, 'accept_lan', _('Accept LAN Access'),
			_('When selected, it can be accessed from LAN, this will not be safe!'));
		o.modalonly = true;
		o = srv.option(form.ListValue, 'loglevel', _('Log Level'));
		o.modalonly = true;
		o.default = 'info';
		['debug', 'info', 'warn', 'error'].forEach(v => o.value(v));
		o.depends('log', '1');

		// users
		usr = m.section(form.GridSection, 'user', _('Users Manager'));
		usr.addremove = true;
		usr.anonymous = true;
		usr.sortable = true;
		usr.rowcolors = true;
		usr.modaltitle = _('Edit User');

		o = usr.option(form.Value, 'username', _('Username'));
		o.rmempty = false;
		o = usr.option(form.Value, 'password', _('Password'));
		o.password = true;
		o = usr.option(form.Value, 'uuid', 'UUID');
		o.datatype = 'uuid';
		o = usr.option(form.Button, 'gen_uuid', _('Generate UUID'));
		o.inputtitle = _('Generate');
		o.inputstyle = 'positive';
		o.onclick = function (ev, section_id) {
			const self = this;
			return momo.genUuid().then((res) => {
				if (!res || !res.uuid) return;
				const uuid = self.section.getOption('uuid');
				if (uuid) uuid.getUIElement(section_id).setValue(res.uuid);
			});
		};

		o = usr.option(form.Value, 'wireguard_public_key', _('WireGuard Public Key'));
		o.modalonly = true;
		o = usr.option(form.Value, 'wireguard_private_key', _('WireGuard Private Key'));
		o.modalonly = true;
		o = usr.option(form.Button, 'gen_wg_key', _('Generate key'));
		o.modalonly = true;
		o.inputtitle = _('Generate');
		o.inputstyle = 'positive';
		o.onclick = function (ev, section_id) {
			const self = this;
			return momo.genWgKeypair().then((res) => {
				if (!res || !res.private_key) return;
				const priv = self.section.getOption('wireguard_private_key');
				const pub = self.section.getOption('wireguard_public_key');
				if (priv) priv.getUIElement(section_id).setValue(res.private_key);
				if (pub) pub.getUIElement(section_id).setValue(res.public_key);
			});
		};
		o = usr.option(form.Value, 'wireguard_pre_shared_key', _('WireGuard Pre Shared Key'));
		o.modalonly = true;
		o = usr.option(form.DynamicList, 'allowed_ips', _('WireGuard Allowed IPs'));
		o.modalonly = true;

		poll.add(function () {
			return L.resolveDefault(momo.serverStatus(), {}).then(function (map) {
				document.querySelectorAll('.momo-srv-status').forEach(function (el) {
					const running = !!map[el.dataset.section];
					el.style.color = running ? 'green' : 'red';
					el.textContent = running ? _('Running') : _('Not Running');
				});
			});
		});

		return m.render();
	}
});
