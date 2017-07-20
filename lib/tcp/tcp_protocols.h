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
#ifndef TCP_PROTOCOLS_H_
#define TCP_PROTOCOLS_H_

#include "proto_manager.h"

void register_360safeguard(LPIModuleMap *mod_map);
void register_4d(LPIModuleMap *mod_map);
void register_acestream(LPIModuleMap *mod_map);
void register_afp(LPIModuleMap *mod_map);
void register_airdroid(LPIModuleMap *mod_map);
void register_airmedia(LPIModuleMap *mod_map);
void register_akamai_tcp(LPIModuleMap *mod_map);
void register_amp(LPIModuleMap *mod_map);
void register_appearin(LPIModuleMap *mod_map);
void register_apple_push(LPIModuleMap *mod_map);
void register_ares(LPIModuleMap *mod_map);
void register_badbaidu(LPIModuleMap *mod_map);
void register_bitcoin(LPIModuleMap *mod_map);
void register_bitextend(LPIModuleMap *mod_map);
void register_bittorrent(LPIModuleMap *mod_map);
void register_blackdesert(LPIModuleMap *mod_map);
void register_blizzard(LPIModuleMap *mod_map);
void register_btsync(LPIModuleMap *mod_map);
void register_cacaoweb(LPIModuleMap *mod_map);
void register_cgp(LPIModuleMap *mod_map);
void register_chatango(LPIModuleMap *mod_map);
void register_cisco_vpn(LPIModuleMap *mod_map);
void register_clashofclans(LPIModuleMap *mod_map);
void register_clubbox(LPIModuleMap *mod_map);
void register_cod_waw(LPIModuleMap *mod_map);
void register_conquer(LPIModuleMap *mod_map);
void register_crashplan(LPIModuleMap *mod_map);
void register_crossfire_tcp(LPIModuleMap *mod_map);
void register_cryptic(LPIModuleMap *mod_map);
void register_cvs(LPIModuleMap *mod_map);
void register_dash(LPIModuleMap *mod_map);
void register_dell_backup(LPIModuleMap *mod_map);
void register_destiny(LPIModuleMap *mod_map);
void register_diablo3(LPIModuleMap *mod_map);
void register_dianping_tcp(LPIModuleMap *mod_map);
void register_directconnect(LPIModuleMap *mod_map);
void register_dns_tcp(LPIModuleMap *mod_map);
void register_dogecoin(LPIModuleMap *mod_map);
void register_douyu(LPIModuleMap *mod_map);
void register_duelingnetwork(LPIModuleMap *mod_map);
void register_dvrns(LPIModuleMap *mod_map);
void register_dxp(LPIModuleMap *mod_map);
void register_ea_games(LPIModuleMap *mod_map);
void register_emule(LPIModuleMap *mod_map);
void register_eye(LPIModuleMap *mod_map);
void register_facebook_turn(LPIModuleMap *mod_map);
void register_fb_message(LPIModuleMap *mod_map);
void register_ffxiv(LPIModuleMap *mod_map);
void register_flash(LPIModuleMap *mod_map);
void register_fring(LPIModuleMap *mod_map);
void register_ftpcontrol(LPIModuleMap *mod_map);
void register_ftpdata(LPIModuleMap *mod_map);
void register_fuckcoin(LPIModuleMap *mod_map);
void register_funshion_tcp(LPIModuleMap *mod_map);
void register_gamespy_tcp(LPIModuleMap *mod_map);
void register_giop(LPIModuleMap *mod_map);
void register_git(LPIModuleMap *mod_map);
void register_glupteba(LPIModuleMap *mod_map);
void register_gnutella(LPIModuleMap *mod_map);
void register_goku(LPIModuleMap *mod_map);
void register_googlehangouts(LPIModuleMap *mod_map);
void register_graalonlineera(LPIModuleMap *mod_map);
void register_guildwars2(LPIModuleMap *mod_map);
void register_hamachi(LPIModuleMap *mod_map);
void register_harveys(LPIModuleMap *mod_map);
void register_hearthstone(LPIModuleMap *mod_map);
void register_hola(LPIModuleMap *mod_map);
void register_http_badport(LPIModuleMap *mod_map);
void register_http(LPIModuleMap *mod_map);
void register_http_nonstandard(LPIModuleMap *mod_map);
void register_https(LPIModuleMap *mod_map);
void register_http_tunnel(LPIModuleMap *mod_map);
void register_ica(LPIModuleMap *mod_map);
void register_id(LPIModuleMap *mod_map);
void register_idrivesync(LPIModuleMap *mod_map);
void register_imap(LPIModuleMap *mod_map);
void register_imaps(LPIModuleMap *mod_map);
void register_imesh(LPIModuleMap *mod_map);
void register_invalid(LPIModuleMap *mod_map);
void register_invalid_bittorrent(LPIModuleMap *mod_map);
void register_invalid_http(LPIModuleMap *mod_map);
void register_invalid_pop(LPIModuleMap *mod_map);
void register_invalid_smtp(LPIModuleMap *mod_map);
void register_ipop(LPIModuleMap *mod_map);
void register_ipsharkk(LPIModuleMap *mod_map);
void register_irc(LPIModuleMap *mod_map);
void register_java(LPIModuleMap *mod_map);
void register_jedi(LPIModuleMap *mod_map);
void register_kakao(LPIModuleMap *mod_map);
void register_kankan_tcp(LPIModuleMap *mod_map);
void register_kaseya(LPIModuleMap *mod_map);
void register_kaspersky(LPIModuleMap *mod_map);
void register_kik(LPIModuleMap *mod_map);
void register_kuaibo(LPIModuleMap *mod_map);
void register_ldap(LPIModuleMap *mod_map);
void register_lifeforge(LPIModuleMap *mod_map);
void register_line(LPIModuleMap *mod_map);
void register_llp2p(LPIModuleMap *mod_map);
void register_maplestory_china(LPIModuleMap *mod_map);
void register_maxicloud(LPIModuleMap *mod_map);
void register_message4u(LPIModuleMap *mod_map);
void register_minecraft(LPIModuleMap *mod_map);
void register_mitglieder(LPIModuleMap *mod_map);
void register_mms(LPIModuleMap *mod_map);
void register_mongo(LPIModuleMap *mod_map);
void register_mp2p(LPIModuleMap *mod_map);
void register_msn(LPIModuleMap *mod_map);
void register_msnc(LPIModuleMap *mod_map);
void register_msnv(LPIModuleMap *mod_map);
void register_munin(LPIModuleMap *mod_map);
void register_mysql(LPIModuleMap *mod_map);
void register_mystery_100_star(LPIModuleMap *mod_map);
void register_mystery_8000(LPIModuleMap *mod_map);
void register_mystery_9000(LPIModuleMap *mod_map);
void register_mystery_conn(LPIModuleMap *mod_map);
void register_mystery_iG(LPIModuleMap *mod_map);
void register_mystery_pspr(LPIModuleMap *mod_map);
void register_mystery_rxxf(LPIModuleMap *mod_map);
void register_mystery_symantec(LPIModuleMap *mod_map);
void register_mzinga(LPIModuleMap *mod_map);
void register_ncsoft(LPIModuleMap *mod_map);
void register_ndt_tput(LPIModuleMap *mod_map);
void register_netbios(LPIModuleMap *mod_map);
void register_netcat_cctv(LPIModuleMap *mod_map);
void register_netmfp(LPIModuleMap *mod_map);
void register_nntp(LPIModuleMap *mod_map);
void register_nntps(LPIModuleMap *mod_map);
void register_norton_backup(LPIModuleMap *mod_map);
void register_notes_rpc(LPIModuleMap *mod_map);
void register_tcp_no_payload(LPIModuleMap *mod_map);
void register_omegle(LPIModuleMap *mod_map);
void register_openvpn(LPIModuleMap *mod_map);
void register_ourworld(LPIModuleMap *mod_map);
void register_palringo(LPIModuleMap *mod_map);
void register_paltalk(LPIModuleMap *mod_map);
void register_pandatv(LPIModuleMap *mod_map);
void register_pando(LPIModuleMap *mod_map);
void register_pdbox(LPIModuleMap *mod_map);
void register_pop3(LPIModuleMap *mod_map);
void register_pop3s(LPIModuleMap *mod_map);
void register_postgresql(LPIModuleMap *mod_map);
void register_pptp(LPIModuleMap *mod_map);
void register_psn_store(LPIModuleMap *mod_map);
void register_qcloud_ilvb(LPIModuleMap *mod_map);
void register_qq_tcp(LPIModuleMap *mod_map);
void register_qqdownload(LPIModuleMap *mod_map);
void register_qqlive_tcp(LPIModuleMap *mod_map);
void register_qvod(LPIModuleMap *mod_map);
void register_razor(LPIModuleMap *mod_map);
void register_rbls(LPIModuleMap *mod_map);
void register_rdp(LPIModuleMap *mod_map);
void register_realvnc(LPIModuleMap *mod_map);
void register_rejection(LPIModuleMap *mod_map);
void register_relay(LPIModuleMap *mod_map);
void register_revolver_nblbt(LPIModuleMap *mod_map);
void register_rfb(LPIModuleMap *mod_map);
void register_rpcscan(LPIModuleMap *mod_map);
void register_rsync(LPIModuleMap *mod_map);
void register_rtmp(LPIModuleMap *mod_map);
void register_rtsp(LPIModuleMap *mod_map);
void register_runescape(LPIModuleMap *mod_map);
void register_s7comm(LPIModuleMap *mod_map);
void register_second_life(LPIModuleMap *mod_map);
void register_shoutcast(LPIModuleMap *mod_map);
void register_silkroadonline(LPIModuleMap *mod_map);
void register_sip(LPIModuleMap *mod_map);
void register_skype_tcp(LPIModuleMap *mod_map);
void register_smb(LPIModuleMap *mod_map);
void register_smtp(LPIModuleMap *mod_map);
void register_smtps(LPIModuleMap *mod_map);
void register_socks4(LPIModuleMap *mod_map);
void register_socks5(LPIModuleMap *mod_map);
void register_spdy(LPIModuleMap *mod_map);
void register_speedin(LPIModuleMap *mod_map);
void register_speedtest(LPIModuleMap *mod_map);
void register_spotify(LPIModuleMap *mod_map);
void register_ssh(LPIModuleMap *mod_map);
void register_ssl(LPIModuleMap *mod_map);
void register_steam(LPIModuleMap *mod_map);
void register_stun_tcp(LPIModuleMap *mod_map);
void register_supl(LPIModuleMap *mod_map);
void register_svn(LPIModuleMap *mod_map);
void register_tankix(LPIModuleMap *mod_map);
void register_taobao(LPIModuleMap *mod_map);
void register_tds(LPIModuleMap *mod_map);
void register_teamviewer(LPIModuleMap *mod_map);
void register_telecomkey(LPIModuleMap *mod_map);
void register_telegram(LPIModuleMap *mod_map);
void register_telnet(LPIModuleMap *mod_map);
void register_telnet_exploit(LPIModuleMap *mod_map);
void register_tencent_games(LPIModuleMap *mod_map);
void register_tensafe(LPIModuleMap *mod_map);
void register_tera(LPIModuleMap *mod_map);
void register_tetrisonline(LPIModuleMap *mod_map);
void register_thedivision(LPIModuleMap *mod_map);
void register_tip(LPIModuleMap *mod_map);
void register_tor(LPIModuleMap *mod_map);
void register_tpkt_generic(LPIModuleMap *mod_map);
void register_trackmania(LPIModuleMap *mod_map);
void register_trion(LPIModuleMap *mod_map);
void register_trojan_win32_generic_sb(LPIModuleMap *mod_map);
void register_trojan_zeroaccess(LPIModuleMap *mod_map);
void register_twitcasting(LPIModuleMap *mod_map);
void register_twitch_irc(LPIModuleMap *mod_map);
void register_vainglory(LPIModuleMap *mod_map);
void register_viber(LPIModuleMap *mod_map);
void register_vodlocker(LPIModuleMap *mod_map);
void register_vpnunlimited_tcp(LPIModuleMap *mod_map);
void register_warcraft3(LPIModuleMap *mod_map);
void register_web_junk(LPIModuleMap *mod_map);
void register_weblogic(LPIModuleMap *mod_map);
void register_wechat(LPIModuleMap *mod_map);
void register_weibo(LPIModuleMap *mod_map);
void register_weiqi(LPIModuleMap *mod_map);
void register_whatsapp(LPIModuleMap *mod_map);
void register_whois(LPIModuleMap *mod_map);
void register_winmx(LPIModuleMap *mod_map);
void register_wns(LPIModuleMap *mod_map);
void register_wow(LPIModuleMap *mod_map);
void register_wuala(LPIModuleMap *mod_map);
void register_xiami(LPIModuleMap *mod_map);
void register_xmpp(LPIModuleMap *mod_map);
void register_xmpps(LPIModuleMap *mod_map);
void register_xunlei(LPIModuleMap *mod_map);
void register_xunlei_accel(LPIModuleMap *mod_map);
void register_xymon(LPIModuleMap *mod_map);
void register_yahoo(LPIModuleMap *mod_map);
void register_yahoo_error(LPIModuleMap *mod_map);
void register_yahoo_games(LPIModuleMap *mod_map);
void register_yahoo_webcam(LPIModuleMap *mod_map);
void register_youku_tcp(LPIModuleMap *mod_map);
void register_yy_tcp(LPIModuleMap *mod_map);
void register_zabbix(LPIModuleMap *mod_map);
void register_zero_facebook(LPIModuleMap *mod_map);
void register_zoom_tcp(LPIModuleMap *mod_map);
void register_zynga(LPIModuleMap *mod_map);

#endif
