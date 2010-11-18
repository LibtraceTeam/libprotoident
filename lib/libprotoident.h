#ifndef LIBPROTOIDENT_H_
#define LIBPROTOIDENT_H_

#include <libtrace.h>

#ifdef __cplusplus 
extern "C" {
#endif

/* Protocol categories - most l7 protocols fall into a broader category that
 * describes what they are used for, e.g. P2P, Web, Mail etc.
 */
typedef enum {
	LPI_CATEGORY_WEB,
	LPI_CATEGORY_CHAT,
	LPI_CATEGORY_MAIL,
	LPI_CATEGORY_P2P,
	LPI_CATEGORY_P2P_STRUCTURE,	/* Maintenance of P2P networks */
	LPI_CATEGORY_SECURITY,
	LPI_CATEGORY_ECOMMERCE,
	LPI_CATEGORY_GAMING,
	LPI_CATEGORY_ENCRYPT,		/* Encrypted traffic that is not
					   clearly part of another category */
	LPI_CATEGORY_MONITORING,	/* Network measurement / monitoring */
	LPI_CATEGORY_NEWS,
	LPI_CATEGORY_MALWARE,
	LPI_CATEGORY_ANTIVIRUS,
	LPI_CATEGORY_ANTISPAM,
	LPI_CATEGORY_VOIP,
	LPI_CATEGORY_TUNNELLING,	/* Tunnelling protocols */
	LPI_CATEGORY_NAT,		/* NAT traversal protocols */
	LPI_CATEGORY_STREAMING,
	LPI_CATEGORY_SERVICES,		/* Basic services, e.g. DNS, NTP */
	LPI_CATEGORY_DATABASES,
	LPI_CATEGORY_FILES,
	LPI_CATEGORY_REMOTE,		/* Remote access, e.g. SSH, telnet */
	LPI_CATEGORY_TELCO,		/* Telco services aside from VOIP, e.g
					   SMS protocols */
	LPI_CATEGORY_ICMP,
	LPI_CATEGORY_NOPAYLOAD,
	LPI_CATEGORY_UNSUPPORTED,
	LPI_CATEGORY_UNKNOWN,
	LPI_CATEGORY_NO_CATEGORY,	/* Protocol has not been placed into a
					   category yet */
	LPI_CATEGORY_LAST
} lpi_category_t;


typedef enum {
        /* TCP Protocols */
        LPI_PROTO_HTTP,
        LPI_PROTO_SMTP,
        LPI_PROTO_BITTORRENT,
        LPI_PROTO_IRC,
        LPI_PROTO_NCSOFT,      /* NCSoft proprietary protocol */
        LPI_PROTO_DC,          /* DirectConnect */
        LPI_PROTO_EMULE,
        LPI_PROTO_GNUTELLA,
        LPI_PROTO_SSH,
        LPI_PROTO_HTTPS,
        LPI_PROTO_RAZOR,       /* Razor database updates */
        LPI_PROTO_POP3,
        LPI_PROTO_SSL,         /* SSL that isn't HTTPS */
        LPI_PROTO_MSN,
        LPI_PROTO_DNS,
        LPI_PROTO_IMAP,
        LPI_PROTO_RTSP,
        LPI_PROTO_ID,          /* Identification protocol */
        LPI_PROTO_YAHOO,
        LPI_PROTO_ICQ,
        LPI_PROTO_TELNET,
        LPI_PROTO_RDP,         /* Windows remote desktop protocol */
        LPI_PROTO_HTTP_MS,     /* Microsoft Exchange extensions to HTTP */
        LPI_PROTO_TDS,         /* MS SQL Server protocol */
        LPI_PROTO_RPC_SCAN,    /* Port 135 exploit attempt */
        LPI_PROTO_SMB,         /* Server Message Block protocol e.g. samba */
        LPI_PROTO_WARCRAFT3,
        LPI_PROTO_ETRUST,      /* Updates for the eTrust virus scanner */
        LPI_PROTO_FTP_CONTROL, /* FTP control e.g. port 21 or 2121 */
        LPI_PROTO_FTP_DATA,
        LPI_PROTO_EYE,         /* Yahoo Game Server Browser */
        LPI_PROTO_ARES,        /* Ares peer-to-peer protocol */
        LPI_PROTO_AR,          /* ar archives, usually Debian .deb files */
        LPI_PROTO_BULK,        /* Bulk one-way transfers e.g. passive FTP */
        LPI_PROTO_NNTP,        /* Newsfeeds */
        LPI_PROTO_NAPSTER,
        LPI_PROTO_BNCS,        /* Battle.net Chat Server */
        LPI_PROTO_RFB,         /* Remote Frame Buffer protocol */
        LPI_PROTO_YAHOO_WEBCAM,/* Webcam over Yahoo Messenger */
        LPI_PROTO_ICA,         /* Citrix ICA */
        LPI_PROTO_NETBIOS,
        LPI_PROTO_KMS,         /* Possibly a vista activation service */
        LPI_PROTO_MS_DS,
        LPI_PROTO_SIP,         /* Session Initiation Protocol*/
        LPI_PROTO_MZINGA,
        LPI_PROTO_TCP_XML,
        LPI_PROTO_GOKUCHAT,
        LPI_PROTO_XUNLEI,
        LPI_PROTO_DXP,
        LPI_PROTO_HAMACHI,
        LPI_PROTO_BLIZZARD,
        LPI_PROTO_MSNV,        /* MSN Voice */
        LPI_PROTO_BITEXT,      /* BitTorrent extensions */
        LPI_PROTO_MITGLIEDER,  /* Mitglieder trojan */
        LPI_PROTO_TOR,         /* TOR (The Onion Router) */
        LPI_PROTO_MYSQL,
        LPI_PROTO_HTTP_TUNNEL, /* Tunnelling via HTTP */
        LPI_PROTO_RSYNC,
        LPI_PROTO_NOTES_RPC,   /* Lotus Notes RPC (Domino) */
        LPI_PROTO_AZUREUS,     /* Azureus Extension */
	LPI_PROTO_PANDO,	/* Pando P2P protocol */
	LPI_PROTO_FLASH,	/* Flash Player specific behaviour */
	LPI_PROTO_STEAM,	/* Steam TCP download, i.e. downloading games */
	LPI_PROTO_TRACKMANIA, 	/* Trackmania control protocol */
	LPI_PROTO_CONQUER,	/* Conquer Online game */
	LPI_PROTO_RTMP,		/* Adobe RTMP */
	LPI_PROTO_TIP,		/* Transaction Internet Protocol */
	LPI_PROTO_P2P_HTTP,	/* P2P over HTTP, a la KaZaA and Gnutella */
	LPI_PROTO_HARVEYS,	/* Photo transfers for Harveys Real Estate */
	LPI_PROTO_SHOUTCAST,
	LPI_PROTO_HTTP_BADPORT,	/* HTTP over port 443, leading to failure */
	LPI_PROTO_POSTGRESQL,	/* Postgresql protocol */
	LPI_PROTO_WOW,		/* World of Warcraft */
	LPI_PROTO_M4U,		/* Message4U (Aus SMS service) */
	LPI_PROTO_RBLS,		/* Realtime Block List updates */
	LPI_PROTO_OPENVPN,
	LPI_PROTO_TELECOMKEY,	/* Proto used to talk to telecomkey.com */
	LPI_PROTO_IMAPS,	/* IMAP over SSL */
	LPI_PROTO_MSNC,		/* MSN Client Protocol */
	LPI_PROTO_YAHOO_ERROR,	/* Yahoo method of dealing with HTTP errors */
	LPI_PROTO_IMESH,	/* iMesh */
	LPI_PROTO_PPTP,		/* MS Tunnelling protocol */

        /* UDP Protocols */
        LPI_PROTO_UDP,
        LPI_PROTO_UDP_SIP,
        LPI_PROTO_UDP_BTDHT,
        LPI_PROTO_UDP_GNUTELLA,
        LPI_PROTO_UDP_DNS,
        LPI_PROTO_UDP_DHCP,
        LPI_PROTO_UDP_QUAKEWORLD,
        LPI_PROTO_UDP_STEAM,
        LPI_PROTO_UDP_STEAM_FRIENDS,
        LPI_PROTO_UDP_WIN_MESSAGE,
        LPI_PROTO_UDP_GAMESPY,
        LPI_PROTO_UDP_EMULE,
        LPI_PROTO_UDP_EYE,
        LPI_PROTO_UDP_RTP,
        LPI_PROTO_UDP_MSN_VIDEO,
        LPI_PROTO_UDP_COD,     /* Call of Duty game protocol */
        LPI_PROTO_UDP_NTP,
	LPI_PROTO_UDP_MP2P,	/* MP2P protocol (Piolet, Manolito etc.) */
	LPI_PROTO_UDP_SPAMFIGHTER,	/* SpamFighter */
	LPI_PROTO_UDP_TRACEROUTE,
	LPI_PROTO_UDP_SECONDLIFE,
	LPI_PROTO_UDP_HL,	/* Halflife */
	LPI_PROTO_UDP_XLSP,	/* XLSP - Xbox Live */
	LPI_PROTO_UDP_DEMONWARE,	/* Company that does game networking */
	LPI_PROTO_UDP_IMESH,	/* iMesh */
	LPI_PROTO_UDP_OPASERV,	/* Opaserv worm */
	LPI_PROTO_UDP_STUN,	/* STUN NAT traversal */
	LPI_PROTO_UDP_SQLEXP,	/* MS SQL Server worm, called SQLExp */
	LPI_PROTO_UDP_MSN_CACHE, /* MSN cache callback protocol */
	LPI_PROTO_UDP_DIABLO2,	/* Diablo 2 game protocol */
	LPI_PROTO_UDP_IPV6,	/* IPv6 tunnelled directly over UDP */
	LPI_PROTO_UDP_ORBIT,	/* Orbit downloader */
	LPI_PROTO_UDP_TEREDO,
	LPI_PROTO_UDP_KADEMLIA,	/* Unknown flavour of kademlia */
	LPI_PROTO_UDP_PANDO,	/* Pando DHT and Peer Exchange */
	LPI_PROTO_UDP_ESP,	/* ESP/IPSec encapsulated in UDP */
	LPI_PROTO_UDP_PSN,	/* Playstation Network */
	LPI_PROTO_UDP_REAL,	/* RDT - the Real Data Transport protocol */
	LPI_PROTO_UDP_GNUTELLA2, /* Gnutella2 */
	LPI_PROTO_UDP_PYZOR,	/* Python implementation of Razor */
	LPI_PROTO_UDP_SKYPE,
	LPI_PROTO_UDP_ISAKMP,	/* ref: RFC 2408 */
	LPI_PROTO_UDP_SNMP,
	LPI_PROTO_UDP_BACKWEB,	/* BackWeb Polite Protocol */
	LPI_PROTO_UDP_STARCRAFT,
	LPI_PROTO_UDP_XFIRE_P2P, /* Xfire P2P protocol */
	LPI_PROTO_UDP_THQ,	/* Protocol used by THQ games */
	LPI_PROTO_UDP_NEWERTH,	/* Heroes of Newerth */
	LPI_PROTO_UDP_LINKPROOF,	/* Linkproof device packets */
	LPI_PROTO_UDP_WORM_22105,	/* Chinese worm that uses port 22105 */
	LPI_PROTO_UDP_EMULE_MYSTERY,	/* Possible emule-related protocol */
	LPI_PROTO_UDP_QQ,		/* Tencent QQ */
	LPI_PROTO_UDP_SLP,	/* Service Location Protocol, RFC 2608 */
	LPI_PROTO_UDP_ESO,	/* Games using Ensemble Studios Online */
	LPI_PROTO_UDP_SSDP,

	LPI_PROTO_ICMP,

        LPI_PROTO_INVALID,     /* No single valid protocol */
	LPI_PROTO_NO_PAYLOAD,
	LPI_PROTO_UNSUPPORTED,
        LPI_PROTO_UNKNOWN,
	LPI_PROTO_LAST		/** ALWAYS have this as the last value */
} lpi_protocol_t;

typedef struct lpi {
	uint32_t payload[2];
	uint32_t seqno[2];
	uint32_t observed[2];
	uint16_t server_port;
	uint16_t client_port;
	uint8_t trans_proto;
	uint32_t payload_len[2];
	uint32_t ips[2];
} lpi_data_t;

int lpi_init_data(lpi_data_t *data);
int lpi_update_data(libtrace_packet_t *packet, lpi_data_t *data, uint8_t dir);
const char *lpi_print(lpi_protocol_t proto);
lpi_category_t lpi_categorise(lpi_protocol_t proto);
const char *lpi_print_category(lpi_category_t category);
lpi_protocol_t lpi_guess_protocol(lpi_data_t *data);
#ifdef __cplusplus 
}
#endif
#endif
