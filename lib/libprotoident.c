#include <stdio.h>
#include <assert.h>
#include <libtrace.h>
#include "libprotoident.h"
#include "proto_tcp.h"
#include "proto_udp.h"

int lpi_init_data(lpi_data_t *data) {

	data->payload[0] = 0;
	data->payload[1] = 0;
	data->server_port = 0;
	data->client_port = 0;
	data->trans_proto = 0;
	data->payload_len[0] = 0;
	data->payload_len[1] = 0;

}

int lpi_update_data(libtrace_packet_t *packet, lpi_data_t *data, uint8_t dir) {

	char *payload = NULL;
	uint32_t psize = 0;
	uint32_t rem = 0;
	uint8_t proto = 0;
	void *transport;
	uint32_t four_bytes;
	
	if (data->payload_len[dir] != 0)
		return 0;
	
	transport = trace_get_transport(packet, &proto, &rem);
	if (transport == NULL || rem == 0)
		return 0;		

	if (data->server_port == 0) {
		data->server_port = trace_get_destination_port(packet);
		data->client_port = trace_get_source_port(packet);
	}

	if (data->trans_proto == 0)
		data->trans_proto = proto;
	
	if (proto == 6) {
		libtrace_tcp_t *tcp = (libtrace_tcp_t *)transport;
		if (tcp->rst)
			return 0;
		payload = (char *)trace_get_payload_from_tcp(tcp, &rem);
	}

	if (proto == 17) {
		libtrace_udp_t *udp = (libtrace_udp_t *)transport;
		payload = (char *)trace_get_payload_from_udp(udp, &rem);
	}

	psize = trace_get_payload_length(packet);

	if (payload == NULL)
		return 0;
	if (psize <= 0)
		return 0;
	
	four_bytes = ntohl((*(uint32_t *)payload));
	
	if (psize < 4) {
		four_bytes = four_bytes >> (8 * (4 - psize));		
		four_bytes = four_bytes << (8 * (4 - psize));		
	}

	assert(data->payload[dir] == 0);
	data->payload[dir] = htonl(four_bytes);
	data->payload_len[dir] = psize;

	return 1;

}

lpi_protocol_t lpi_guess_protocol(lpi_data_t *data) {

	switch(data->trans_proto) {
		case TRACE_IPPROTO_ICMP:
			return LPI_PROTO_ICMP;
		case TRACE_IPPROTO_TCP:
			return guess_tcp_protocol(data);
		case TRACE_IPPROTO_UDP:
			return guess_udp_protocol(data);
		default:
			return LPI_PROTO_UNSUPPORTED;
	}

	return LPI_PROTO_UNSUPPORTED;
}
	

const char *lpi_print(lpi_protocol_t proto) {
	switch(proto) {
		case LPI_PROTO_INVALID:
			return "Invalid";
		case LPI_PROTO_UNKNOWN:
			return "Unknown_TCP";
		case LPI_PROTO_UDP:
			return "Unknown_UDP";
		case LPI_PROTO_NO_PAYLOAD:
			return "No_Payload";
		case LPI_PROTO_UNSUPPORTED:
			return "Unsupported";
		case LPI_PROTO_ICMP:
			return "ICMP";

		/* TCP Protocols */
		case LPI_PROTO_HTTP:
			return "HTTP";
		case LPI_PROTO_SMTP:
			return "SMTP";
		case LPI_PROTO_SMTPSPAM:
			return "SpamSMTP";
		case LPI_PROTO_SMTPREJECT:
			return "RejectedSMTP";
		case LPI_PROTO_DC:
			return "DirectConnect";
		case LPI_PROTO_BITTORRENT:
			return "BitTorrent";
		case LPI_PROTO_EMULE:
			return "eMule";
		case LPI_PROTO_NCSOFT:
			return "NCSoft";
		case LPI_PROTO_IRC:
			return "IRC";
		case LPI_PROTO_SSH:
			return "SSH";
		case LPI_PROTO_GNUTELLA:
			return "Gnutella";
		case LPI_PROTO_POP3:
			return "POP3";
		case LPI_PROTO_RAZOR:
			return "Razor";
		case LPI_PROTO_HTTPS:
			return "HTTPS";
		case LPI_PROTO_SSL:
			return "SSL";
		case LPI_PROTO_MSN:
			return "MSN";
		case LPI_PROTO_DNS:
			return "DNS";
		case LPI_PROTO_IMAP:
			return "IMAP";
                case LPI_PROTO_RTSP:
                        return "RTSP";
                case LPI_PROTO_ID:
                        return "ID_Protocol";
                case LPI_PROTO_YAHOO:
                        return "Yahoo";
                case LPI_PROTO_ICQ:
                        return "ICQ";
                case LPI_PROTO_TELNET:
                        return "Telnet";
                case LPI_PROTO_RTMP:
                        return "RTMP";
                case LPI_PROTO_RDP:
                        return "RDP";
                case LPI_PROTO_HTTP_IMAGE:
                        return "WebImage";
                case LPI_PROTO_HTTP_MS:
                        return "Microsoft_HTTP";
                case LPI_PROTO_TDS:
                        return "TDS";
                 case LPI_PROTO_RPC_SCAN:
                        return "RPC_Exploit";
                case LPI_PROTO_SMB:
                        return "SMB";
                case LPI_PROTO_WARCRAFT3:
                        return "Warcraft3";
                case LPI_PROTO_ETRUST:
                        return "eTrust_Update";
                case LPI_PROTO_FTP_CONTROL:
                        return "FTP_Control";
                case LPI_PROTO_FTP_DATA:
                        return "FTP_Data";
                case LPI_PROTO_EYE:
                        return "AllSeeingEye";
                case LPI_PROTO_ARES:
                        return "Ares";
                case LPI_PROTO_AR:
                        return "ar_Archive";
                case LPI_PROTO_BULK:
                        return "BulkOneWay";
                case LPI_PROTO_NNTP:
                        return "NNTP";
                case LPI_PROTO_NAPSTER:
                        return "Napster";
                case LPI_PROTO_BNCS:
                        return "Battle.net_Chat";
                case LPI_PROTO_RFB:
                        return "RFB";
                case LPI_PROTO_YAHOO_WEBCAM:
                        return "Yahoo_Webcam";
                case LPI_PROTO_ICA:
                        return "CitrixICA";
                case LPI_PROTO_NETBIOS:
                        return "Netbios_Session";
                case LPI_PROTO_KMS:
                        return "KMS";
                case LPI_PROTO_MS_DS:
                        return "Microsoft_DS";
                case LPI_PROTO_SIP:
                        return "SIP";
                case LPI_PROTO_MZINGA:
                        return "Mzinga";
                case LPI_PROTO_TCP_XML:
                        return "XML";
                case LPI_PROTO_XUNLEI:
                        return "Xunlei";
                case LPI_PROTO_GOKUCHAT:
                        return "GokuChat";
                case LPI_PROTO_DXP:
                        return "Silverplatter_DXP";
                case LPI_PROTO_HAMACHI:
                        return "Hamachi";
                case LPI_PROTO_BLIZZARD:
                        return "Blizzard";
                case LPI_PROTO_MSNV:
                        return "MSN_Voice";
                case LPI_PROTO_BITEXT:
                        return "BitTorrent_Extension";
                case LPI_PROTO_MITGLIEDER:
                        return "Mitglieder_Trojan";
                case LPI_PROTO_TOR:
                        return "TOR";
                case LPI_PROTO_MYSQL:
                        return "MySQL";
                case LPI_PROTO_HTTP_TUNNEL:
                        return "HTTP_Tunnel";
                case LPI_PROTO_SMTP_SCAN:
                        return "SMTP_Scan";
                case LPI_PROTO_RSYNC:
                        return "Rsync";
                case LPI_PROTO_NOTES_RPC:
                        return "Lotus_Notes_RPC";
                case LPI_PROTO_AZUREUS:
                        return "Azureus";
		case LPI_PROTO_PANDO:
			return "Pando";
		case LPI_PROTO_FLASH:
			return "Flash_Player";
		case LPI_PROTO_STEAM:
			return "Steam_TCP";

                /* UDP Protocols */
                case LPI_PROTO_UDP_SIP:
                        return "SIP";
                case LPI_PROTO_UDP_BTDHT:
                        return "BitTorrent_UDP";
                case LPI_PROTO_UDP_GNUTELLA:
                        return "Gnutella";
                case LPI_PROTO_UDP_DNS:
                        return "DNS";
                case LPI_PROTO_UDP_DHCP:
                        return "DHCP";
                case LPI_PROTO_UDP_QUAKEWORLD:
                        return "QuakeWorld";
                case LPI_PROTO_UDP_STEAM:
                        return "Steam_UDP";
                case LPI_PROTO_UDP_STEAM_FRIENDS:
                        return "Steam_Friends";
                case LPI_PROTO_UDP_WIN_MESSAGE:
                        return "WindowsMessenger";
                case LPI_PROTO_UDP_GAMESPY:
                        return "Gamespy";
                case LPI_PROTO_UDP_EMULE:
                        return "eMule";
                case LPI_PROTO_UDP_EYE:
                        return "AllSeeingEye";
                case LPI_PROTO_UDP_RTP:
                        return "RTP";
                case LPI_PROTO_UDP_MSN_VIDEO:
                        return "MSN_Video";
                case LPI_PROTO_UDP_COD:
                        return "Call_of_Duty";
                case LPI_PROTO_UDP_NTP:
                        return "NTP";

                default:
                {
                        printf("%d\n",(int)proto);
                        assert(0);
                }
        }
}

