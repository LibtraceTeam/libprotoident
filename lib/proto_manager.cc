/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include "config.h"

#include <glob.h>
#include <dlfcn.h>

#include "proto_manager.h"
#include "tcp/tcp_protocols.h"
#include "udp/udp_protocols.h"

void register_protocol(lpi_module_t *mod, LPIModuleMap *mod_map) {
	LPIModuleMap::iterator it;
	LPIModuleList *ml;

	it = mod_map->find(mod->priority); 

	if (it == mod_map->end()) {
		(*mod_map)[mod->priority] = new LPIModuleList();
		
		it = mod_map->find(mod->priority);
	}
	
	ml = it->second;
	ml->push_back(mod);


}

void free_protocols(LPIModuleMap *mod_map) {

	LPIModuleMap::iterator it;
	LPIModuleList *ml;

	for (it = mod_map->begin(); it != mod_map->end(); it ++) {
		ml = it->second;

		ml->clear();
		delete(ml);
	}
	mod_map->clear();
}

int register_tcp_protocols(LPIModuleMap *mod_map) {

	register_300heroes(mod_map);
	register_360safeguard(mod_map);
	register_4d(mod_map);
	register_acestream(mod_map);
	register_afp(mod_map);
	register_airdroid(mod_map);
	register_airmedia(mod_map);
	register_akamai_tcp(mod_map);
	register_amp(mod_map);
	register_antcoin(mod_map);
	register_appearin(mod_map);
	register_apple_push(mod_map);
	register_ares(mod_map);
	register_badbaidu(mod_map);
	register_baofeng_tcp(mod_map);
	register_beam(mod_map);
	register_bitcoin(mod_map);
	register_bitextend(mod_map);
	register_bittorrent(mod_map);
	register_blackdesert(mod_map);
	register_blizzard(mod_map);
	register_btsync(mod_map);
	register_bwsyncandshare(mod_map);
	register_cacaoweb(mod_map);
	register_cgp(mod_map);
	register_chatango(mod_map);
	register_cisco_vpn(mod_map);
	register_clashofclans(mod_map);
	register_clubbox(mod_map);
	register_cod_waw(mod_map);
	register_conquer(mod_map);
	register_crashplan(mod_map);
	register_crossfire_tcp(mod_map);
	register_cryptic(mod_map);
	register_cvs(mod_map);
	register_dahua_tcp(mod_map);
	register_dash(mod_map);
	register_dell_backup(mod_map);
	register_destiny(mod_map);
	register_diablo3(mod_map);
	register_dianping_tcp(mod_map);
	register_directconnect(mod_map);
	register_dnf(mod_map);
	register_dns_tcp(mod_map);
	register_dogecoin(mod_map);
	register_douyu(mod_map);
	register_douyu_chat(mod_map);
	register_duelingnetwork(mod_map);
	register_dvrns(mod_map);
	register_dxp(mod_map);
	register_ea_games(mod_map);
	register_emule(mod_map);
	register_eye(mod_map);
	register_facebook_turn(mod_map);
	register_fb_message(mod_map);
	register_fbcdn_ssl(mod_map);
	register_ffxiv(mod_map);
	register_filenori(mod_map);
	register_flash(mod_map);
	register_fliggy(mod_map);
	register_fring(mod_map);
	register_ftpcontrol(mod_map);
	register_ftpdata(mod_map);
	register_fuckcoin(mod_map);
	register_funshion_tcp(mod_map);
	register_gamespy_tcp(mod_map);
	register_gcafe_updater(mod_map);
	register_giop(mod_map);
	register_git(mod_map);
	register_glupteba(mod_map);
	register_gnutella(mod_map);
	register_goku(mod_map);
	register_googlehangouts(mod_map);
	register_graalonlineera(mod_map);
	register_guildwars2(mod_map);
	register_hamachi(mod_map);
	register_harveys(mod_map);
	register_hearthstone(mod_map);
	register_hola(mod_map);
	register_hots_tcp(mod_map);
	register_http_badport(mod_map);
	register_http(mod_map);
	register_http_nonstandard(mod_map);
	register_https(mod_map);
	register_http_tunnel(mod_map);
	register_ica(mod_map);
	register_icep(mod_map);
	register_id(mod_map);
	register_idrivesync(mod_map);
	register_ihexin(mod_map);
	register_imap(mod_map);
	register_imaps(mod_map);
	register_imesh(mod_map);
	register_invalid(mod_map);
	register_invalid_bittorrent(mod_map);
	register_invalid_http(mod_map);
	register_invalid_pop(mod_map);
	register_invalid_smtp(mod_map);
	register_ipfs(mod_map);
	register_ipop(mod_map);
	register_ipsharkk(mod_map);
	register_irc(mod_map);
	register_java(mod_map);
	register_jedi(mod_map);
	register_jx3online(mod_map);
	register_kakao(mod_map);
	register_kankan_tcp(mod_map);
	register_kaseya(mod_map);
	register_kaspersky(mod_map);
	register_kik(mod_map);
	register_kingofglory_tcp(mod_map);
	register_kuaibo(mod_map);
	register_ldap(mod_map);
	register_lifeforge(mod_map);
	register_line(mod_map);
	register_litecoin(mod_map);
	register_llp2p(mod_map);
	register_maplestory_china(mod_map);
	register_maxicloud(mod_map);
	register_message4u(mod_map);
	register_minecraft(mod_map);
	//register_mitglieder(mod_map);
	register_mms(mod_map);
	register_mongo(mod_map);
	register_mp2p(mod_map);
	register_msn(mod_map);
	register_msnc(mod_map);
	register_msnv(mod_map);
	register_munin(mod_map);
	register_mysql(mod_map);
	//register_mystery_8000(mod_map);
	//register_mystery_9000(mod_map);
	//register_mystery_conn(mod_map);
	//register_mystery_iG(mod_map);
	//register_mystery_pspr(mod_map);
	//register_mystery_rxxf(mod_map);
	//register_mystery_symantec(mod_map);
	register_mzinga(mod_map);
	register_naverp2p(mod_map);
	register_ncsoft(mod_map);
	register_ndt_tput(mod_map);
	register_netbios(mod_map);
	register_netcat_cctv(mod_map);
	register_netmfp(mod_map);
	register_nntp(mod_map);
	register_nntps(mod_map);
	register_nomachine(mod_map);
	register_norton_backup(mod_map);
	register_notes_rpc(mod_map);
	register_tcp_no_payload(mod_map);
	register_tcp_no_firstpkt(mod_map);
	register_nsq(mod_map);
	register_omegle(mod_map);
	register_openvpn(mod_map);
	register_ourworld(mod_map);
	register_palringo(mod_map);
	register_paltalk(mod_map);
	register_pandatv(mod_map);
	register_pando(mod_map);
	register_pathofexile(mod_map);
	register_pdbox(mod_map);
	register_pop3(mod_map);
	register_pop3s(mod_map);
	register_postgresql(mod_map);
	register_pptp(mod_map);
	register_psn_store(mod_map);
	register_qcloud_ilvb(mod_map);
	register_qq_tcp(mod_map);
	register_qqdownload(mod_map);
	register_qqlive_tcp(mod_map);
	register_qqspeedmobile_tcp(mod_map);
	register_qvod(mod_map);
        register_rabbitmq(mod_map);
        register_razor(mod_map);
	register_rbls(mod_map);
	register_rdp(mod_map);
	register_realmofthemadgod(mod_map);
	register_realvnc(mod_map);
	register_rejection(mod_map);
	register_relay(mod_map);
	register_remote_manipulator(mod_map);
	register_revolver_nblbt(mod_map);
	register_rfb(mod_map);
	register_rpcscan(mod_map);
	register_rrtv(mod_map);
	register_rsync(mod_map);
	register_rtmp(mod_map);
	register_rtsp(mod_map);
	register_runescape(mod_map);
	register_s7comm(mod_map);
	register_saprouter(mod_map);
	register_saszombieassault4(mod_map);
	register_second_life(mod_map);
	register_shoutcast(mod_map);
	register_silkroadonline(mod_map);
	register_sip(mod_map);
	register_skyforge(mod_map);
	register_skype_tcp(mod_map);
	register_smb(mod_map);
        register_smite_tcp(mod_map);
	register_smtp(mod_map);
	register_smtps(mod_map);
	register_socks4(mod_map);
	register_socks5(mod_map);
	register_spdy(mod_map);
	register_speedify(mod_map);
	register_speedin(mod_map);
	register_speedtest(mod_map);
	register_spotify(mod_map);
	register_ssh(mod_map);
	register_ssjj(mod_map);
	register_ssl(mod_map);
	register_steam(mod_map);
	register_stratum(mod_map);
	register_stun_tcp(mod_map);
	register_supl(mod_map);
	register_svn(mod_map);
	register_talesrunner(mod_map);
	register_tankionline(mod_map);
	register_tankix(mod_map);
	register_taobao(mod_map);
	register_tds(mod_map);
	register_teamviewer(mod_map);
	register_telecomkey(mod_map);
	register_telegram(mod_map);
	register_telnet(mod_map);
	register_telnet_exploit(mod_map);
	register_tencent_games(mod_map);
	register_tenfivecoin(mod_map);
	register_tensafe(mod_map);
	register_tera(mod_map);
	register_tetrisonline(mod_map);
	register_thedivision(mod_map);
	register_tip(mod_map);
	register_tor(mod_map);
	register_tpkt_generic(mod_map);
	register_trackmania(mod_map);
	register_trion(mod_map);
	register_trojan_win32_generic_sb(mod_map);
	register_trojan_zeroaccess(mod_map);
	register_twitcasting(mod_map);
	register_twitch_irc(mod_map);
	register_utherverse(mod_map);
	register_vainglory(mod_map);
	register_viber(mod_map);
	register_vmware(mod_map);
	register_vodlocker(mod_map);
	register_vpnrobot_tcp(mod_map);
	register_vpnunlimited_tcp(mod_map);
	register_warcraft3(mod_map);
	register_web_junk(mod_map);
	register_webex_stun(mod_map);
	register_weblogic(mod_map);
	register_wechat(mod_map);
	register_weibo(mod_map);
	register_weiqi(mod_map);
	register_whatsapp(mod_map);
	register_whois(mod_map);
	register_winmx(mod_map);
	register_wizard101(mod_map);
	register_wns(mod_map);
	register_wow(mod_map);
	register_wuala(mod_map);
	register_xiami(mod_map);
	register_xmpp(mod_map);
	register_xmpps(mod_map);
	register_xunlei(mod_map);
	register_xunlei_accel(mod_map);
	register_xymon(mod_map);
	register_yahoo(mod_map);
	register_yahoo_error(mod_map);
	register_yahoo_games(mod_map);
	register_yahoo_webcam(mod_map);
	register_youku_tcp(mod_map);
	register_yy_tcp(mod_map);
	register_zabbix(mod_map);
	register_zero_facebook(mod_map);
	register_zoom_tcp(mod_map);
	register_zynga(mod_map);
	return 0;
}

int register_udp_protocols(LPIModuleMap *mod_map) {

	register_360cn(mod_map);
	register_360p2p(mod_map);
	register_aachen_udp(mod_map);
	register_acercloud(mod_map);
	register_akamai(mod_map);
	register_akamai_transfer(mod_map);
	register_amanda(mod_map);
	register_apple_facetime_init(mod_map);
	register_ard(mod_map);
	register_ares_udp(mod_map);
	register_arksurvival(mod_map);
	register_arma_server(mod_map);
	register_arma3_server(mod_map);
	register_assettocorsa(mod_map);
	register_avast_secure_dns(mod_map);
	register_bacnet(mod_map);
	register_backweb(mod_map);
	register_baiduyun_p2p(mod_map);
	register_baofeng_udp(mod_map);
	register_battlefield(mod_map);
	register_bjnp(mod_map);
	register_bmdp(mod_map);
	register_btsync_udp(mod_map);
	register_cacaoweb_udp(mod_map);
	register_canon_mfnp(mod_map);
	register_callofduty(mod_map);
	register_chargen_exploit(mod_map);
	register_checkpoint_rdp(mod_map);
	register_chivalry(mod_map);
	register_cirn(mod_map);
	register_cisco_ipsec(mod_map);
	register_cisco_sslvpn(mod_map);
	register_cloudflare_warp(mod_map);
	register_codmobile(mod_map);
	register_combatarms(mod_map);
	register_combatarms_p2p(mod_map);
	register_contract_wars(mod_map);
	register_crossfire(mod_map);
	register_crossout(mod_map);
	register_csgo(mod_map);
	register_csoriginal(mod_map);
	register_dahua(mod_map);
	register_db2(mod_map);
	register_dcc_udp(mod_map);
	register_demonware(mod_map);
	register_destiny_udp(mod_map);
	register_dhcp(mod_map);
	register_dht_dict(mod_map);
	register_dht_other(mod_map);
	register_diablo2(mod_map);
	register_dianping_udp(mod_map);
	register_dianshijia(mod_map);
	register_directconnect_udp(mod_map);
	register_discord(mod_map);
	register_dns_udp(mod_map);
	register_dota2(mod_map);
	register_doyo(mod_map);
	register_driveshare(mod_map);
	register_dtls(mod_map);
	register_emule_udp(mod_map);
	//register_emule_weak_udp(mod_map);
	register_epson(mod_map);
	//register_eso(mod_map);
	register_esp_encap(mod_map);
	register_eye_udp(mod_map);
	register_fasp(mod_map);
	register_feitwo(mod_map);
	register_forticlient_sslvpn(mod_map);
	register_fortinet(mod_map);
	register_foscam(mod_map);
	register_freechal(mod_map);
	register_freefire(mod_map);
	register_funshion_udp(mod_map);
	register_gamespy(mod_map);
	register_ganglia(mod_map);
	register_gangsofspace(mod_map);
	register_garena(mod_map);
	register_gearsofwar(mod_map);
	register_gnutella_udp(mod_map);
	register_gnutella2_udp(mod_map);
	register_gnutella_weak(mod_map);
	register_gotomeeting(mod_map);
	register_gprs_tunnel(mod_map);
	register_gsm(mod_map);
	register_h1z1(mod_map);
	register_halflife(mod_map);
	register_haloonline(mod_map);
	register_hamachi_udp(mod_map);
	register_heliborne(mod_map);
	register_heroesevolved(mod_map);
	register_heroes_generals(mod_map);
	register_hollachat(mod_map);
	register_hots(mod_map);
	register_icp(mod_map);
	register_imesh_udp(mod_map);
	register_ipmsg(mod_map);
	//register_ipv6_udp(mod_map);
	register_isakmp(mod_map);
	register_jedi_academy(mod_map);
	register_jedi_udp(mod_map);
	register_kademlia(mod_map);
	register_kankan(mod_map);
	register_kaspersky_udp(mod_map);
	register_kazaa(mod_map);
	register_kingofglory_udp(mod_map);
	register_kugou(mod_map);
	register_l2tp(mod_map);
	register_lansync_udp(mod_map);
	register_ldap_ad(mod_map);
	register_line_udp(mod_map);
	register_linkproof(mod_map);
	register_loadout(mod_map);
	register_lol(mod_map);
	register_mdns(mod_map);
	register_merakicloud(mod_map);
	register_moh(mod_map);
	register_moonhunters(mod_map);
	register_mp2p_udp(mod_map);
	register_msn_cache(mod_map);
	register_msn_video(mod_map);
	register_msoffice_mac(mod_map);
	register_mta(mod_map);
	//register_mystery_05(mod_map);
	//register_mystery_0660(mod_map);
	//register_mystery_0d(mod_map);
	//register_mystery_45(mod_map);
	//register_mystery_61_72(mod_map);
	//register_mystery_8000_udp(mod_map);
	//register_mystery_99(mod_map);
	//register_mystery_e9(mod_map);
	//register_mystery_qq(mod_map);
	register_n2ping(mod_map);
	register_natpmp(mod_map);
	register_netbios_udp(mod_map);
	register_netcat_cctv_udp(mod_map);
	register_netcore_scan(mod_map);
	register_netflow(mod_map);
	register_newerth(mod_map);
	register_nintendo(mod_map);
	register_noction(mod_map);
	register_noe(mod_map);
	register_norton(mod_map);
	register_ntp(mod_map);
	register_ntp_reflect(mod_map);
	register_nwn(mod_map);
	register_opaserv(mod_map);
	register_openvpn_udp(mod_map);
	register_orbit_udp(mod_map);
	register_overwatch(mod_map);
	register_paladins(mod_map);
	register_pando_udp(mod_map);
	register_panipani(mod_map);
	register_planetside2(mod_map);
	register_portmap_rpc(mod_map);
	register_pplive(mod_map);
	register_ppstream(mod_map);
	//register_probable_gnutella(mod_map);
	register_ps4_remoteplay(mod_map);
	register_psn(mod_map);
	register_punkbuster(mod_map);
	register_pyzor(mod_map);
	register_qq(mod_map);
	register_qqlive(mod_map);
	register_qqpcmgr(mod_map);
	register_qqspeedmobile_udp(mod_map);
	register_quake(mod_map);
	register_quic(mod_map);
	register_qvod_udp(mod_map);
	register_radius(mod_map);
	register_ramsey_dash(mod_map);
	register_rdp_udp(mod_map);
	register_real(mod_map);
	register_risingstorm(mod_map);
	register_roblox(mod_map);
	register_robocraft(mod_map);
	register_rocket_league(mod_map);
	register_rrshare(mod_map);
	register_rtcp(mod_map);
	register_rtmfp(mod_map);
	register_rtp(mod_map);
	register_rulesofsurvival(mod_map);
	register_sanandreas_mp(mod_map);
	register_second_life_udp(mod_map);
	register_serialnumberd(mod_map);
	register_sip_udp(mod_map);
	register_skype(mod_map);
	register_slp(mod_map);
        register_smite(mod_map);
	register_snapvpn(mod_map);
	register_snmp(mod_map);
	register_sopcast(mod_map);
	register_spamfighter(mod_map);
	register_spotify_bcast(mod_map);
	register_sql_worm(mod_map);
	register_ssdp(mod_map);
	register_starcitizen(mod_map);
	register_starcraft(mod_map);
	register_starleaf(mod_map);
	register_steamfriends(mod_map);
	register_steam_localbroadcast(mod_map);
	register_steam_inhomebroadcast(mod_map);
	register_steam_udp(mod_map);
	register_storm_worm(mod_map);
	register_stun(mod_map);
	register_syslog(mod_map);
	register_talesrunner_udp(mod_map);
	register_teamspeak(mod_map);
	register_teamviewer_udp(mod_map);
	register_teredo(mod_map);
	register_tf2(mod_map);
	register_tftp(mod_map);
	register_thecrew(mod_map);
	register_thq(mod_map);
	register_torchlight2(mod_map);
	register_tox(mod_map);
	register_traceroute(mod_map);
	register_tremulous(mod_map);
	register_turbovpn(mod_map);
	register_tvants(mod_map);
	register_ubisoft_games(mod_map);
	register_udp_no_payload(mod_map);
	register_umeye(mod_map);
	register_unreal(mod_map);
	register_ventrilo(mod_map);
	register_viber_udp(mod_map);
	register_vivox(mod_map);
	register_vpnmaster(mod_map);
	register_vpnrobot_udp(mod_map);
	register_vxworks_exploit(mod_map);
	register_warthunder(mod_map);
	register_webex(mod_map);
	register_wechat_udp(mod_map);
	register_winmessage(mod_map);
	register_wireguard(mod_map);
	register_wolfet(mod_map);
	register_worm_22105(mod_map);
	register_xfire_p2p(mod_map);
	register_xlsp(mod_map);
	register_xunlei_jsq(mod_map);
	register_xunlei_udp(mod_map);
	register_xunyou(mod_map);
	register_youdao_dict(mod_map);
	register_youku_udp(mod_map);
	register_yuanfudao(mod_map);
	register_yy_udp(mod_map);
	register_zalo_call(mod_map);
	register_zeroaccess_udp(mod_map);
	register_zoom(mod_map);
	return 0;
}

static void register_list_names(LPIModuleList *ml, LPINameMap *names) {
	LPIModuleList::iterator it; 

	for (it = ml->begin(); it != ml->end(); it ++) {
		lpi_module_t *mod = *it;

		(*names)[mod->protocol] = mod->name;
	}

}

void register_names(LPIModuleMap *mods, LPINameMap *names) {

	LPIModuleMap::iterator it;

	for (it = mods->begin(); it != mods->end(); it ++) {
		register_list_names(it->second, names);
	}

}

void init_other_protocols(LPINameMap *name_map) {

	lpi_icmp = new lpi_module_t;

	lpi_icmp->protocol = LPI_PROTO_ICMP;
	lpi_icmp->category = LPI_CATEGORY_ICMP;
	lpi_icmp->name = "ICMP";
	lpi_icmp->priority = 255;
	lpi_icmp->lpi_callback = NULL;
	(*name_map)[lpi_icmp->protocol] = lpi_icmp->name;

	lpi_unknown_tcp = new lpi_module_t;

	lpi_unknown_tcp->protocol = LPI_PROTO_UNKNOWN;
	lpi_unknown_tcp->category = LPI_CATEGORY_UNKNOWN;
	lpi_unknown_tcp->name = "Unknown_TCP";
	lpi_unknown_tcp->priority = 255;
	lpi_unknown_tcp->lpi_callback = NULL;
	(*name_map)[lpi_unknown_tcp->protocol] = lpi_unknown_tcp->name;
	
	lpi_unknown_udp = new lpi_module_t;

	lpi_unknown_udp->protocol = LPI_PROTO_UDP;
	lpi_unknown_udp->category = LPI_CATEGORY_UNKNOWN;
	lpi_unknown_udp->name = "Unknown_UDP";
	lpi_unknown_udp->priority = 255;
	lpi_unknown_udp->lpi_callback = NULL;
	(*name_map)[lpi_unknown_udp->protocol] = lpi_unknown_udp->name;

	lpi_unsupported = new lpi_module_t;

	lpi_unsupported->protocol = LPI_PROTO_UNSUPPORTED;
	lpi_unsupported->category = LPI_CATEGORY_UNSUPPORTED;
	lpi_unsupported->name = "Unsupported";
	lpi_unsupported->priority = 255;
	lpi_unsupported->lpi_callback = NULL;
	(*name_map)[lpi_unsupported->protocol] = lpi_unsupported->name;

}

