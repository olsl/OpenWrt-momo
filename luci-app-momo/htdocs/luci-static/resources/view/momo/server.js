'use strict';
'require form';
'require view';
'require uci';

const SS_METHODS = [
	'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
	'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
	'2022-blake3-chacha20-poly1305'
];

const PROTOCOLS = [
	['mixed', 'Mixed'],
	['socks', 'Socks'],
	['http', 'HTTP'],
	['shadowsocks', 'Shadowsocks'],
	['vmess', 'VMess'],
	['vless', 'VLESS'],
	['trojan', 'Trojan'],
	['anytls', 'AnyTLS'],
	['hysteria2', 'Hysteria2'],
	['wireguard', 'WireGuard'],
	['snell', 'Snell'],
	['direct', 'Direct']
];

const TLS_PROTOCOLS = ['http', 'vmess', 'vless', 'trojan', 'anytls'];

return view.extend({
	load: function () {
		return uci.load('momo_server').then(() => uci.sections('momo_server', 'user'));
	},

	render: function (userSections) {
		let m, s, srv, usr, o;

		m = new form.Map('momo_server', _('Server-Side'));

		// global
		s = m.section(form.NamedSection, 'global', 'global', _('Server-Side'));
		o = s.option(form.Flag, 'enable', _('Enable'));
		o.rmempty = false;

		const userOptions = (userSections || []).map(u => [u['.name'], u.username || u['.name']]);

		// servers
		srv = m.section(form.TableSection, 'server', _('Servers Manager'));
		srv.addremove = true;
		srv.anonymous = true;
		srv.sortable = true;

		o = srv.option(form.Flag, 'enable', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = srv.option(form.Value, 'remarks', _('Remarks'));

		o = srv.option(form.ListValue, 'protocol', _('Protocol'));
		PROTOCOLS.forEach(([v, t]) => o.value(v, t));

		o = srv.option(form.Value, 'port', _('Listen Port'));
		o.datatype = 'port';

		o = srv.option(form.DynamicList, 'users', _('User'));
		userOptions.forEach(([id, label]) => o.value(id, label));

		// custom raw config
		o = srv.option(form.Flag, 'custom', _('Use Custom Config'));
		o = srv.option(form.TextValue, 'custom_config', _('Custom Config') + ' (JSON)');
		o.rows = 10;
		o.wrap = 'off';
		o.depends('custom', '1');

		// shadowsocks
		o = srv.option(form.ListValue, 'ss_method', _('Encrypt Method'));
		SS_METHODS.forEach(v => o.value(v));
		o.depends('protocol', 'shadowsocks');
		o = srv.option(form.Value, 'ss_password', _('Password'));
		o.depends('protocol', 'shadowsocks');

		// vless
		o = srv.option(form.ListValue, 'flow', _('Flow'));
		o.value('', _('Disable'));
		o.value('xtls-rprx-vision');
		o.depends('protocol', 'vless');

		// direct
		o = srv.option(form.ListValue, 'd_protocol', _('Destination protocol'));
		o.value('tcp'); o.value('udp'); o.value('tcp,udp');
		o.depends('protocol', 'direct');
		o = srv.option(form.Value, 'd_address', _('Destination address'));
		o.depends('protocol', 'direct');
		o = srv.option(form.Value, 'd_port', _('Destination port'));
		o.datatype = 'port';
		o.depends('protocol', 'direct');

		// TLS
		o = srv.option(form.Flag, 'tls', _('TLS'));
		TLS_PROTOCOLS.forEach(p => o.depends('protocol', p));

		o = srv.option(form.Flag, 'reality', _('REALITY'));
		o.depends('tls', '1');
		o = srv.option(form.Value, 'reality_private_key', _('Private Key'));
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_shortId', _('Short Id'));
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_handshake_server', _('Handshake Server'));
		o.default = 'google.com';
		o.depends('reality', '1');
		o = srv.option(form.Value, 'reality_handshake_server_port', _('Handshake Server Port'));
		o.datatype = 'port';
		o.default = '443';
		o.depends('reality', '1');

		o = srv.option(form.ListValue, 'alpn', _('ALPN'));
		o.default = 'default';
		o.value('default', _('Default'));
		['h3', 'h2', 'h3,h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1'].forEach(v => o.value(v));
		o.depends({ tls: '1', reality: '0' });

		o = srv.option(form.Flag, 'tls_use_pem', _('Use PEM'));
		o.depends({ tls: '1', reality: '0' });
		o = srv.option(form.Value, 'tls_certificateFile', _('Path to the certificate file'));
		o.depends({ tls: '1', reality: '0', tls_use_pem: '0' });
		o = srv.option(form.Value, 'tls_keyFile', _('Path to the private key file'));
		o.depends({ tls: '1', reality: '0', tls_use_pem: '0' });
		o = srv.option(form.TextValue, 'tls_certificate', _('TLS Certificate (PEM)'));
		o.rows = 5; o.wrap = 'off';
		o.depends('tls_use_pem', '1');
		o = srv.option(form.TextValue, 'tls_key', _('TLS Private Key (PEM)'));
		o.rows = 5; o.wrap = 'off';
		o.depends('tls_use_pem', '1');

		// transport
		o = srv.option(form.ListValue, 'transport', _('Transport'));
		o.value('tcp', 'TCP'); o.value('http', 'HTTP'); o.value('ws', 'WebSocket');
		o.value('httpupgrade', 'HTTPUpgrade'); o.value('quic', 'QUIC'); o.value('grpc', 'gRPC');
		['shadowsocks', 'vmess', 'vless', 'trojan'].forEach(p => o.depends('protocol', p));

		o = srv.option(form.DynamicList, 'http_host', _('HTTP Host'));
		o.depends('transport', 'http');
		o = srv.option(form.Value, 'http_path', _('HTTP Path'));
		o.depends('transport', 'http');

		o = srv.option(form.Value, 'ws_host', _('WebSocket Host'));
		o.depends('transport', 'ws');
		o = srv.option(form.Value, 'ws_path', _('WebSocket Path'));
		o.depends('transport', 'ws');
		o = srv.option(form.Value, 'ws_earlyDataHeaderName', _('Early data header name'));
		o.placeholder = 'Sec-WebSocket-Protocol';
		o.depends('transport', 'ws');

		o = srv.option(form.Value, 'httpupgrade_host', _('HTTPUpgrade Host'));
		o.depends('transport', 'httpupgrade');
		o = srv.option(form.Value, 'httpupgrade_path', _('HTTPUpgrade Path'));
		o.depends('transport', 'httpupgrade');

		o = srv.option(form.Value, 'grpc_serviceName', 'ServiceName');
		o.depends('transport', 'grpc');

		// mux
		o = srv.option(form.Flag, 'mux', _('Mux'));
		['vmess', 'vless', 'shadowsocks', 'trojan'].forEach(p => o.depends('protocol', p));
		o = srv.option(form.Flag, 'tcpbrutal', _('TCP Brutal'));
		o.depends('mux', '1');
		o = srv.option(form.Value, 'tcpbrutal_up_mbps', _('Max upload Mbps'));
		o.default = '10';
		o.depends('tcpbrutal', '1');
		o = srv.option(form.Value, 'tcpbrutal_down_mbps', _('Max download Mbps'));
		o.default = '50';
		o.depends('tcpbrutal', '1');

		// hysteria2
		o = srv.option(form.ListValue, 'hysteria2_obfs_type', _('Obfs Type'));
		o.value('', _('Disable')); o.value('salamander'); o.value('gecko');
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Value, 'hysteria2_obfs_password', _('Obfs Password'));
		o.depends('hysteria2_obfs_type', 'salamander');
		o.depends('hysteria2_obfs_type', 'gecko');
		o = srv.option(form.Value, 'hysteria2_up_mbps', _('Max upload Mbps'));
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Value, 'hysteria2_down_mbps', _('Max download Mbps'));
		o.depends('protocol', 'hysteria2');
		o = srv.option(form.Flag, 'hysteria2_ignore_client_bandwidth', _('Client BBR Flow Control'));
		o.depends('protocol', 'hysteria2');

		// wireguard
		o = srv.option(form.Flag, 'wireguard_system_interface', _('System interface'));
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Value, 'wireguard_mtu', 'MTU');
		o.default = '1408';
		o.depends('protocol', 'wireguard');
		o = srv.option(form.DynamicList, 'wireguard_local_address', _('Local Address'));
		o.depends('protocol', 'wireguard');
		o = srv.option(form.Value, 'wireguard_private_key', _('Private Key'));
		o.depends('protocol', 'wireguard');

		// snell
		o = srv.option(form.ListValue, 'snell_version', _('Version'));
		o.value('5'); o.value('6');
		o.depends('protocol', 'snell');
		o = srv.option(form.Value, 'snell_psk', _('Pre shared key'));
		o.depends('protocol', 'snell');
		o = srv.option(form.ListValue, 'snell_obfs_mode', _('Obfs'));
		o.value('none'); o.value('http');
		o.depends({ protocol: 'snell', snell_version: '5' });
		o = srv.option(form.ListValue, 'snell_mode', _('Mode'));
		o.value('default'); o.value('unshaped'); o.value('unsafe-raw');
		o.depends({ protocol: 'snell', snell_version: '6' });

		// firewall / log
		o = srv.option(form.Flag, 'firewall_allow', _('Firewall Allow'));
		o = srv.option(form.Value, 'firewall_allow_src', _('Source zone'));
		o.default = 'wan';
		o.depends('firewall_allow', '1');
		o = srv.option(form.Flag, 'accept_lan', _('Accept LAN Access'));
		o = srv.option(form.Flag, 'log', _('Log'));
		o.default = '1';
		o.rmempty = false;
		o = srv.option(form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'info';
		['debug', 'info', 'warn', 'error'].forEach(v => o.value(v));
		o.depends('log', '1');

		// users
		usr = m.section(form.TableSection, 'user', _('Users Manager'));
		usr.addremove = true;
		usr.anonymous = true;
		usr.sortable = true;

		o = usr.option(form.Value, 'username', _('Username'));
		o = usr.option(form.Value, 'password', _('Password'));
		o.password = true;
		o = usr.option(form.Value, 'uuid', 'UUID');
		o.datatype = 'uuid';
		o = usr.option(form.Value, 'wireguard_public_key', _('WireGuard Public Key'));
		o = usr.option(form.Value, 'wireguard_pre_shared_key', _('WireGuard Pre Shared Key'));
		o = usr.option(form.DynamicList, 'allowed_ips', _('WireGuard Allowed IPs'));

		return m.render();
	}
});
