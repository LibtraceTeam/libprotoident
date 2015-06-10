/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 */


#ifndef LIBPROTOIDENT_H_
#define LIBPROTOIDENT_H_

#include <libtrace.h>
#include <pthread.h>
#include <list>

#if __GNUC__ >= 3 
#ifndef PRINTF
#  define DEPRECATED __attribute__((deprecated))
#  define SIMPLE_FUNCTION __attribute__((pure))
#  define UNUSED __attribute__((unused))
#  define PACKED __attribute__((packed))
#  define PRINTF(formatpos,argpos) __attribute__((format(printf,formatpos,argpos)))
#endif
#else
#ifndef PRINTF
#  define DEPRECATED
#  define SIMPLE_FUNCTION
#  define UNUSED
#  define PACKED 
#  define PRINTF(formatpos,argpos) 
#endif
#endif

#define DEFAULT_MAXTHREADS 10

#ifdef __cplusplus 
extern "C" {
#endif

/* Protocol categories - most l7 protocols fall into a broader category that
 * describes what they are used for, e.g. P2P, Web, Mail etc.
 */
typedef enum {
	LPI_CATEGORY_WEB,		/* HTTP-based protocols */
	LPI_CATEGORY_CHAT,		/* Instant messaging and chatrooms */
	LPI_CATEGORY_MAIL,		/* E-mail */
	LPI_CATEGORY_P2P,		/* Peer-to-peer uploads and downloads */
	LPI_CATEGORY_P2P_STRUCTURE,	/* Maintenance of P2P networks */
	LPI_CATEGORY_KEY_EXCHANGE,	/* Protocols used to exchange and
					   manage cryptographic keys, e.g.
					   ISAKMP */
	LPI_CATEGORY_ECOMMERCE,		/* Financial transaction protocols */
	LPI_CATEGORY_GAMING,		/* Game protocols */
	LPI_CATEGORY_ENCRYPT,		/* Encrypted traffic that is not
					   clearly part of another category */
	LPI_CATEGORY_MONITORING,	/* Network measurement / monitoring */
	LPI_CATEGORY_NEWS,		/* Newsgroup protocols, e.g. NNTP */
	LPI_CATEGORY_MALWARE,		/* Viruses, trojans etc. */
	LPI_CATEGORY_SECURITY,		/* Antivirus and firewall updates */
	LPI_CATEGORY_ANTISPAM,		/* Anti-spam software update protocols
					 */
	LPI_CATEGORY_VOIP,		/* Voice chat and Internet telephony 
					   protocols */
	LPI_CATEGORY_TUNNELLING,	/* Tunnelling protocols */
	LPI_CATEGORY_NAT,		/* NAT traversal protocols */
	LPI_CATEGORY_STREAMING,		/* Streaming media protocols */
	LPI_CATEGORY_SERVICES,		/* Basic services, e.g. DNS, NTP */
	LPI_CATEGORY_DATABASES,		/* Database remote access protocols */
	LPI_CATEGORY_FILES,		/* Non-P2P file transfer protocols */
	LPI_CATEGORY_REMOTE,		/* Remote access, e.g. SSH, telnet */
	LPI_CATEGORY_TELCO,		/* Telco services aside from VOIP, e.g
					   SMS protocols */
	LPI_CATEGORY_P2PTV,		/* P2P TV, e.g. PPLive */
	LPI_CATEGORY_RCS,		/* Revision Control */
	LPI_CATEGORY_LOGGING,		/* Logging */
	LPI_CATEGORY_PRINTING,		/* Network printing */
	LPI_CATEGORY_TRANSLATION,	/* Language translation */
	LPI_CATEGORY_CDN,		/* CDN protocols, e.g. Akamai */
	LPI_CATEGORY_CLOUD,		/* Cloud computing/storage protocols */
	LPI_CATEGORY_NOTIFICATION,	/* Notification / messaging protocols */
	LPI_CATEGORY_SERIALISATION,	/* Transfer of programming "objects" */
	LPI_CATEGORY_BROADCAST,		/* Protocols usually broadcast to the
					   local network */
	LPI_CATEGORY_LOCATION,		/* Location-related services / GPS */
	LPI_CATEGORY_CACHING,		/* Proxy cache protocols and similar */
	LPI_CATEGORY_ICMP,		/* ICMP */
	LPI_CATEGORY_MIXED,		/* Different protos in each direction */
	LPI_CATEGORY_NOPAYLOAD,		/* No payload observed */
	LPI_CATEGORY_UNSUPPORTED,	/* Transport protocol unsupported */
	LPI_CATEGORY_UNKNOWN,		/* Protocol could not be identified */
	LPI_CATEGORY_NO_CATEGORY,	/* Protocol has not been placed into a
					   category yet */
	LPI_CATEGORY_LAST		/* Must always be last */
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
        LPI_PROTO_TDS,         /* MS SQL Server protocol */
        LPI_PROTO_RPC_SCAN,    /* Port 135 exploit attempt */
        LPI_PROTO_SMB,         /* Server Message Block protocol e.g. samba */
        LPI_PROTO_WARCRAFT3,
        LPI_PROTO_ETRUST,      /* Updates for the eTrust virus scanner */
        LPI_PROTO_FTP_CONTROL, /* FTP control e.g. port 21 or 2121 */
        LPI_PROTO_FTP_DATA,
        LPI_PROTO_EYE,         /* Yahoo Game Server Browser */
        LPI_PROTO_ARES,        /* Ares peer-to-peer protocol */
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
	LPI_PROTO_NONSTANDARD_HTTP, /* HTTP on unconventional port numbers */
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
	LPI_PROTO_AFP,		/* Apple Filing Protocol */
	LPI_PROTO_PDBOX,	/* Korean P2P TV protocol */
	LPI_PROTO_EA_GAMES,	/* EA Games protocol */
	LPI_PROTO_ZYNGA,	/* Protocol used by Zynga games */
	LPI_PROTO_CLUBBOX,	/* Another Korean file sharing protocol */
	LPI_PROTO_WINMX,	/* WinMX */
	LPI_PROTO_INVALID_BT,	/* Bittorrent in one direction but not other */
	LPI_PROTO_WEBLOGIC,	/* Weblogic server */
	LPI_PROTO_INVALID_HTTP,	/* HTTP server sending raw HTML */
	LPI_PROTO_COD_WAW,	/* Call of Duty: World at War TCP */
	LPI_PROTO_MP2P,
	LPI_PROTO_SVN,
	LPI_PROTO_SOCKS5,
	LPI_PROTO_SOCKS4,
	LPI_PROTO_INVALID_SMTP,
	LPI_PROTO_MMS,		/* Microsoft Media Server */
	LPI_PROTO_CISCO_VPN,	/* Cisco VPN protocol */
	LPI_PROTO_WEB_JUNK,	/* Clients communicating with web servers
				   using non-HTTP */
	LPI_PROTO_CVS,
	LPI_PROTO_LDAP,		/* LDAP */
	LPI_PROTO_INVALID_POP3,	/* POP commands send to an SMTP server */
	LPI_PROTO_TEAMVIEWER,
	LPI_PROTO_XMPP,		/* a.k.a. Jabber */
	LPI_PROTO_SECONDLIFE,	/* SecondLife over TCP */
	LPI_PROTO_KASEYA,
	LPI_PROTO_KASPERSKY,
	LPI_PROTO_JEDI,		/* Citrix Jedi */
	LPI_PROTO_CGP,		/* Citrix CGP */
	LPI_PROTO_YOUKU,
	LPI_PROTO_STUN,
	LPI_PROTO_XYMON,
	LPI_PROTO_MUNIN,
	LPI_PROTO_TROJAN_WIN32_GENERIC_SB,
	LPI_PROTO_PALTALK,
	LPI_PROTO_ZABBIX,
	LPI_PROTO_AKAMAI, 
	LPI_PROTO_GAMESPY, 
	LPI_PROTO_WUALA,
	LPI_PROTO_TROJAN_ZEROACCESS, 
	LPI_PROTO_DVRNS,
	LPI_PROTO_CHATANGO, 
	LPI_PROTO_OMEGLE,
	LPI_PROTO_TELNET_EXPLOIT, 
	LPI_PROTO_POP3S,		/* POP3 over TLS/SSL */ 
	LPI_PROTO_PSN_STORE,		
	LPI_PROTO_SKYPE_TCP,		/* Skype TCP sessions */		
	LPI_PROTO_APPLE_PUSH,		/* Apple push notifications */ 
	LPI_PROTO_XMPPS,		/* XMPP over TLS/SSL */
	LPI_PROTO_SMTPS,		/* Legacy Secure SMTP */ 
	LPI_PROTO_NNTPS,		/* NNTP over TLS/SSL */		
	LPI_PROTO_JAVA,			/* Serialised Java Objects */
	LPI_PROTO_IPOP,			/* IP over P2P */
	LPI_PROTO_SPOTIFY,
	LPI_PROTO_RUNESCAPE,	
	LPI_PROTO_WHOIS,
	LPI_PROTO_VIBER,
	LPI_PROTO_FRING,
	LPI_PROTO_PALRINGO,
	LPI_PROTO_CRYPTIC,		/* Games by Cryptic */
	LPI_PROTO_SUPL,
	LPI_PROTO_MINECRAFT,
	LPI_PROTO_TPKT,
        LPI_PROTO_QVOD,
        LPI_PROTO_KIK,
        LPI_PROTO_WHATSAPP,
        LPI_PROTO_WECHAT,
	LPI_PROTO_FUNSHION,

        /* UDP Protocols */
        LPI_PROTO_UDP,
        LPI_PROTO_UDP_SIP,
        LPI_PROTO_UDP_BTDHT,
        LPI_PROTO_UDP_GNUTELLA,
        LPI_PROTO_UDP_DNS,
        LPI_PROTO_UDP_DHCP,
        LPI_PROTO_UDP_QUAKE,
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
	LPI_PROTO_UDP_QQ,		/* Tencent QQ */
	LPI_PROTO_UDP_SLP,	/* Service Location Protocol, RFC 2608 */
	LPI_PROTO_UDP_ESO,	/* Games using Ensemble Studios Online */
	LPI_PROTO_UDP_SSDP,
	LPI_PROTO_UDP_NETBIOS,	/* Netbios lookup */
	LPI_PROTO_UDP_CP_RDP,	/* Checkpoint RDP */
	LPI_PROTO_UDP_VENTRILO,	/* Ventrilo VoiceChat */
	LPI_PROTO_UDP_MTA,	/* Multitheftauto */
	LPI_PROTO_UDP_PPLIVE,
	LPI_PROTO_UDP_JEDI_ACADEMY,	/* Jedi Academy game */
	LPI_PROTO_UDP_MOH,	/* Medal of Honor game */
	LPI_PROTO_UDP_TREMULOUS, /* Tremulous - free OSS FPS */
	LPI_PROTO_UDP_VIVOX,	/* Vivox voice chat */
	LPI_PROTO_UDP_IPMSG,	/* IPMsg messenger */
	LPI_PROTO_UDP_TEAMSPEAK,
	LPI_PROTO_UDP_DC,	/* DirectConnect UDP commands */
	LPI_PROTO_UDP_FREECHAL,	/* FreeChal P2P */
	LPI_PROTO_UDP_XUNLEI,
	LPI_PROTO_UDP_KAZAA,
	LPI_PROTO_UDP_NORTON,	/* Norton Antivirus probe */
	LPI_PROTO_UDP_CISCO_VPN,	/* Cisco VPN (port 10000) */
	LPI_PROTO_UDP_RTCP,
	LPI_PROTO_UDP_UNREAL,	/* Unreal server query protocol */
	LPI_PROTO_UDP_TFTP,
	LPI_PROTO_UDP_GARENA,	/* A gaming platform */
	LPI_PROTO_UDP_PPSTREAM,	/* PPStream - Chinese P2PTV */
	LPI_PROTO_UDP_FORTINET,	/* Fortinet update protocol */
	LPI_PROTO_UDP_TVANTS,	/* TVants P2PTV - no longer active */
	LPI_PROTO_UDP_STORM_WORM,
	LPI_PROTO_UDP_BATTLEFIELD,	/* Battlefield series of games */
	LPI_PROTO_UDP_SOPCAST,
	LPI_PROTO_UDP_SERIALNUMBERD,
	LPI_PROTO_UDP_LDAP_AD,
	LPI_PROTO_UDP_RTMFP,
	LPI_PROTO_UDP_L2TP,
	LPI_PROTO_UDP_SYSLOG,
	LPI_PROTO_UDP_AKAMAI,
	LPI_PROTO_UDP_RADIUS,
	LPI_PROTO_UDP_HAMACHI,
	LPI_PROTO_UDP_BJNP,	/* Canon BJNP printing protocol */
	LPI_PROTO_UDP_KASPERSKY,
	LPI_PROTO_UDP_GSM,
	LPI_PROTO_UDP_JEDI,	/* Citrix Jedi */
	LPI_PROTO_UDP_YOUKU,
	LPI_PROTO_UDP_YOUDAO_DICT,
	LPI_PROTO_UDP_DRIVESHARE,
	LPI_PROTO_UDP_CIRN,	/* Carpathia Intelligent Routing Network */
	LPI_PROTO_UDP_NEVERWINTER,
	LPI_PROTO_UDP_QQLIVE,
	LPI_PROTO_UDP_TEAMVIEWER,
	LPI_PROTO_UDP_ARES,
	LPI_PROTO_UDP_EPSON,
	LPI_PROTO_UDP_AKAMAI_TRANSFER,
	LPI_PROTO_UDP_DCC,
	LPI_PROTO_UDP_AMANDA,
	LPI_PROTO_UDP_NETFLOW,
	LPI_PROTO_UDP_ZEROACCESS,
	LPI_PROTO_UDP_VXWORKS_EXPLOIT,
	LPI_PROTO_UDP_APPLE_FACETIME_INIT,
	LPI_PROTO_UDP_STEAM_LOCALBROADCAST,	
	/* ^Protocol used by Steam to discover clients on the local network */
	LPI_PROTO_UDP_LANSYNC,	/* LANSync, used by DropBox */
	LPI_PROTO_UDP_MSOFFICE_MAC,	/* MS Office for Mac anti-piracy */
	LPI_PROTO_UDP_SPOTIFY_BROADCAST,
	LPI_PROTO_UDP_MDNS,	/* Multicast DNS */
	LPI_PROTO_UDP_FASP,
	LPI_PROTO_UDP_ROBLOX,
	LPI_PROTO_UDP_OPENVPN,
	LPI_PROTO_UDP_NOE,	/* Alcatel's New Office Environment */
	LPI_PROTO_UDP_VIBER,
	LPI_PROTO_UDP_DTLS,
	LPI_PROTO_UDP_ICP,
	LPI_PROTO_UDP_LOL,	/* League of Legends */
	LPI_PROTO_UDP_SANANDREAS,	/* San Andreas Multiplayer */
	LPI_PROTO_UDP_MFNP,	/* Canon MFNP Printer protocol */
	LPI_PROTO_UDP_FUNSHION, 

	/* Patterns that we can match, but do not know the protocol */
	LPI_PROTO_REJECTION,	/* All responses are 0x02 */
	LPI_PROTO_MYSTERY_9000,	/* Occurs on tcp port 9000 */
	LPI_PROTO_MYSTERY_PSPR,
	LPI_PROTO_MYSTERY_8000,
	LPI_PROTO_MYSTERY_IG,
	LPI_PROTO_MYSTERY_CONN,
	LPI_PROTO_MYSTERY_443,
	LPI_PROTO_MYSTERY_SYMANTEC,
	LPI_PROTO_MYSTERY_RXXF,
	LPI_PROTO_MYSTERY_100_STAR,
	
	LPI_PROTO_UDP_MYSTERY_0D,	
	LPI_PROTO_UDP_MYSTERY_99,
	LPI_PROTO_UDP_MYSTERY_8000,
	LPI_PROTO_UDP_MYSTERY_45,
	LPI_PROTO_UDP_MYSTERY_0660,
	LPI_PROTO_UDP_MYSTERY_E9,
	LPI_PROTO_UDP_MYSTERY_QQ,
	LPI_PROTO_UDP_MYSTERY_61_72,
	LPI_PROTO_UDP_MYSTERY_05,

	LPI_PROTO_ICMP,

        LPI_PROTO_INVALID,     /* No single valid protocol */
	LPI_PROTO_NO_PAYLOAD,
	LPI_PROTO_UNSUPPORTED,
        LPI_PROTO_UNKNOWN,
	LPI_PROTO_LAST		/** ALWAYS have this as the last value */
} lpi_protocol_t;

/* This structure stores all the data needed by libprotoident to identify the
 * application protocol for a flow. Do not change the contents of this struct
 * directly - lpi_update_data() will do that for you - but reading the values
 * should be ok. */
typedef struct lpi {
	uint32_t payload[2];
	bool seen_syn[2];
	uint32_t seqno[2];
	uint32_t observed[2];
	uint16_t server_port;
	uint16_t client_port;
	uint8_t trans_proto;
	uint32_t payload_len[2];
	uint32_t ips[2];
    in6_addr ip6s[2];
} lpi_data_t;

typedef struct lpi_module lpi_module_t;

/* This structure describes an individual LPI module - i.e. a protocol 
 * supported by libprotoident */
struct lpi_module {
        lpi_protocol_t protocol;	/* The protocol ID */
        lpi_category_t category;	/* The category for this protocol */
        const char *name;		/* The protocol name, as a string */
        uint8_t priority;		/* The relative priority for matching
					   this protocol */

	/* The callback function for testing whether a given set of LPI
	 * data matches the ruleset for this protocol */
        bool (*lpi_callback) (lpi_data_t *proto_d, lpi_module_t *module);

};

typedef std::list<lpi_module_t *> ProtoMatchList;

typedef struct lpi_thread {
	int index;
	lpi_module_t *module;
	lpi_data_t *data;
	bool result;
} lpi_thread_t;

typedef std::list<pthread_t> ThreadList;

/* Initialises the LPI library, by registering all the protocol modules.
 *
 * @return 0 if initialisation succeeded, -1 otherwise 
 */
int lpi_init_library(void);

/* Shuts down the LPI library, by de-registering all the protocol modules */
void lpi_free_library(void);

/** Initialises an LPI data structure, setting all the members to appropriate
 *  starting values.
 *
 * @param data	The LPI data structure to be initialised.
 */
void lpi_init_data(lpi_data_t *data);

/** Updates the LPI data structure based on the contents of the packet
 *  provided.
 *
 *  @note The direction must be provided by the caller, as we cannot rely
 *  on trace_get_direction().
 *
 *  @param packet The packet to update the LPI data from.
 *  @param data	The LPI data structure to be updated.
 *  @param dir The direction of the packet - 0 is outgoing, 1 is incoming.
 *
 *  @return 0 if the packet was ignored, 1 if the LPI data was updated.
 */
int lpi_update_data(libtrace_packet_t *packet, lpi_data_t *data, uint8_t dir);

/** Returns a unique string describing the provided protocol.
 *
 * This is essentially a protocol-to-string conversion function.
 *
 * @param proto The protocol that a string representation is required for.
 *
 * @return A pointer to a statically allocated string describing the protocol.
 * This is allocated on the stack, so should be used or copied immediately.
 */
const char *lpi_print(lpi_protocol_t proto);

/** Given a protocol, returns the category that it matches.
 *
 * @param proto The protocol that a category is required for.
 *
 * @return The category that the protocol belongs to.
 */
lpi_category_t lpi_categorise(lpi_module_t *proto);

/** Returns a unique string describing the provided category. 
 *
 * This is essentially a category-to-string conversion function.
 *
 * @param category The category that a string representation is required for.
 *
 * @return A pointer to a statically allocated string describing the category.
 * This is allocated on the stack, so should be used or copied immediately.
 */
const char *lpi_print_category(lpi_category_t category);

/** Using the provided data, attempts to determine the L7 protocol being used
 *  by that flow.
 *
 *  @param data	The LPI data to use when determining the protocol.
 *
 *  @return The LPI module for the protocol that matches the profile described
 *  by the given LPI data. If no protocol matches, the module for either
 *  LPI_UNKNOWN or LPI_UNKNOWN_UDP will be returned, depending on the transport
 *  protocol.
 */
lpi_module_t *lpi_guess_protocol(lpi_data_t *data);

/** Determines whether the protocol matching a given protocol number is no
 *  longer supported by libprotoident.
 *
 *  @param proto The protocol to check
 *
 *  @return true if the protocol is no longer supported, false otherwise.
 *
 *  Some protocols are no longer supported by libprotoident, either because
 *  the rules were found to be producing too many false positives or the 
 *  protocol has been merged with another existing protocol (especially in the
 *  case of mystery protocols). When these cases occur, we don't necessarily
 *  remove the protocol from the enumerated type list, just disable the module
 *  and set the name string for the protocol to "NULL".
 *
 *  This function allows the caller to check if a given protocol value has 
 *  been disabled. This is often handy when reporting stats for all the 
 *  protocol values (see lpi_live for an example), as ideally you would want
 *  to avoid reporting anything for the NULL protocols.
 */
bool lpi_is_protocol_inactive(lpi_protocol_t proto);
#ifdef __cplusplus 
}
#endif
#endif
