#ifndef TCP_PROTOCOLS_H_
#define TCP_PROTOCOLS_H_

#include "proto_manager.h"

void register_ares(LPIModuleMap *mod_map);
void register_bitextend(LPIModuleMap *mod_map);
void register_bittorrent(LPIModuleMap *mod_map);
void register_directconnect(LPIModuleMap *mod_map);
void register_dns_tcp(LPIModuleMap *mod_map);
void register_eye(LPIModuleMap *mod_map);
void register_flash(LPIModuleMap *mod_map);
void register_ftpcontrol(LPIModuleMap *mod_map);
void register_ftpdata(LPIModuleMap *mod_map);
void register_gnutella(LPIModuleMap *mod_map);
void register_harveys(LPIModuleMap *mod_map);
void register_http_badport(LPIModuleMap *mod_map);
void register_http(LPIModuleMap *mod_map);
void register_http_p2p(LPIModuleMap *mod_map);
void register_https(LPIModuleMap *mod_map);
void register_http_tunnel(LPIModuleMap *mod_map);
void register_ica(LPIModuleMap *mod_map);
void register_id(LPIModuleMap *mod_map);
void register_imap(LPIModuleMap *mod_map);
void register_imaps(LPIModuleMap *mod_map);
void register_irc(LPIModuleMap *mod_map);
void register_msn(LPIModuleMap *mod_map);
void register_mzinga(LPIModuleMap *mod_map);
void register_ncsoft(LPIModuleMap *mod_map);
void register_netbios(LPIModuleMap *mod_map);
void register_nntp(LPIModuleMap *mod_map);
void register_tcp_no_payload(LPIModuleMap *mod_map);
void register_pando(LPIModuleMap *mod_map);
void register_pop3(LPIModuleMap *mod_map);
void register_razor(LPIModuleMap *mod_map);
void register_rdp(LPIModuleMap *mod_map);
void register_rfb(LPIModuleMap *mod_map);
void register_rpcscan(LPIModuleMap *mod_map);
void register_rsync(LPIModuleMap *mod_map);
void register_rtsp(LPIModuleMap *mod_map);
void register_shoutcast(LPIModuleMap *mod_map);
void register_sip(LPIModuleMap *mod_map);
void register_smb(LPIModuleMap *mod_map);
void register_smtp(LPIModuleMap *mod_map);
void register_ssh(LPIModuleMap *mod_map);
void register_ssl(LPIModuleMap *mod_map);
void register_steam(LPIModuleMap *mod_map);
void register_telnet(LPIModuleMap *mod_map);
void register_trackmania(LPIModuleMap *mod_map);
void register_warcraft3(LPIModuleMap *mod_map);
void register_yahoo(LPIModuleMap *mod_map);
void register_yahoo_webcam(LPIModuleMap *mod_map);

#endif
