
#include "libprotoident.h"
#include "proto_common.h"
#include "proto_udp.h"

static inline bool match_gamespy(lpi_data_t *data) {

        if (match_str_either(data, "\\sta"))
                return true;
        if (match_str_either(data, "\\inf"))
                return true;
        if (match_str_either(data, "\\gam"))
                return true;
        if (match_str_either(data, "\\hos"))
                return true;
        if (match_str_either(data, "\\bas"))
                return true;

        if (MATCH(data->payload[0], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[0] << 16) == (data->payload[1] & 0xffff0000)))
                return true;
        if (MATCH(data->payload[1], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[1] << 16) == (data->payload[0] & 0xffff0000)))
                return true;

        return false;

}

static inline bool match_mp2p(lpi_data_t *data) {

	/* At least one of the endpoints needs to be on the known port */
	if (data->server_port != 41170 && data->client_port != 41170)
		return false;

	if (match_chars_either(data, 0x3d, 0x4a, 0xd9, ANY))
		return true;
	if (match_chars_either(data, 0x3e, 0x4a, 0xd9, ANY))
		return true;
	if (match_chars_either(data, 0x3d, 0x4b, 0xd9, ANY))
		return true;
	if (match_chars_either(data, 0x3e, 0x4b, 0xd9, ANY))
		return true;

	return false;
	
}		

static inline bool match_rtp(lpi_data_t *data) {
        if (match_chars_either(data, 0x80, 0x80, ANY, ANY) &&
                        match_str_either(data, "\x00\x01\x00\x08"))
		return true;
	
	if (match_chars_either(data, 0x80, 0x60, ANY, ANY) && 
			(data->payload_len[0] == 0 || data->payload_len[1]==0))
		return true;

	return false;

}

static inline bool match_esp_encap(lpi_data_t *data) {

	/* This sucks, as the four bytes are the security association ID for
	 * the flow. We can only really go on port numbers, although we can
	 * identify IKE packets by looking for the Non-ESP marker (which is
	 * all zeroes)
	 *
	 * Just have to match on ports, I guess :(
	 */

	if (data->server_port == 4500 && data->client_port == 4500)
		return true;
	return false;

}

static inline bool match_orbit(lpi_data_t *data) {

	/* There's no nice spec for the Orbit UDP protocol, so I'm just
	 * going to match based on evidence observed thus far */

	if (data->server_port != 20129 && data->client_port != 20129)
		return false;

	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	if (MATCH(data->payload[0], 0xaa, 0x20, 0x04, 0x04)) {
		if (data->payload_len[0] == 36)
			return true;
		return false;
	}
	
	if (MATCH(data->payload[1], 0xaa, 0x20, 0x04, 0x04)) {
		if (data->payload_len[1] == 36)
			return true;
		return false;
	}

	return false;	
}

static inline bool match_sql_worm(lpi_data_t *data) {

	/* The recipient does not reply (with any luck!) */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	if (match_chars_either(data, 0x04, 0x01, 0x01, 0x01))
		return true;

	return false;

}

/*
 * This covers Windows messenger spam over UDP 
 *
 * Ref: http://www.mynetwatchman.com/kb/security/articles/popupspam/netsend.htm
 */
static inline bool match_messenger_spam(lpi_data_t *data) {

	/* The recipient does not reply */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	if (match_chars_either(data, 0x04, 0x00, ANY, 0x00))
		return true;
	return false;
}

/* http://wiki.limewire.org/index.php?title=Out_of_Band_System */
static inline bool match_gnutella_oob(lpi_data_t *data) {

	if (!match_ip_address_both(data))
		return false;
	
	/* Payload size seems to be either 32 or 33 bytes */
	if (data->payload_len[0] == 32 || data->payload_len[1] == 32)
		return true;
	if (data->payload_len[0] == 33 || data->payload_len[1] == 33)
		return true;

	return false;

}

static inline bool match_gnutella(lpi_data_t *data) {

	/* According to http://www.symantec.com/connect/articles/identifying-p2p-users-using-traffic-analysis, Limewire and BearShare (which are based on
	 * Gnutella) will send lots of 23 byte UDP packets when a file transfer
	 * begins */

	/* The UDP communication begins with all zeroes */
	if (!match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00"))
		return false;
	
	/* First packet is 23 bytes, but there can also be no packet in one
	 * direction */

	if (data->payload_len[0] != 0 && data->payload_len[0] != 23)
		return false;
	if (data->payload_len[1] != 0 && data->payload_len[1] != 23)
		return false;

	return true;

}

/* http://xbtt.sourceforge.net/udp_tracker_protocol.html */
static inline bool match_xbt_tracker(lpi_data_t *data) {

	if (data->payload_len[0] != 0 && data->payload_len[0] != 16)
		return false;
	if (data->payload_len[1] != 0 && data->payload_len[1] != 16)
		return false;

	if (!match_chars_either(data, 0x00, 0x00, 0x04, 0x17))
		return false;

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return true;
	
	if (data->payload_len[0] == 16 && data->payload_len[1] == 16 &&
			match_chars_either(data, 0x00, 0x00, 0x00, 0x00))
		return true;

	return false;

}

static inline bool match_steam(lpi_data_t *data) {

        /* Master Server Queries begin with 31 ff 30 2e
         *
         * NOTE: the ff byte can vary depending on the region that the user
         * is querying for, but ff is the "all regions" option and is the
         * typical default. 
         */
        if (match_str_either(data, "\x31\xff\x30\x2e")
                        && match_str_either(data, "\xff\xff\xff\xff")) {
                return true;
        }

        /* Server Info queries are always 53 bytes and begin with ff ff ff ff.
         * The reply also begins with ff ff ff ff but can vary in size */

        if (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") &&
                data->payload_len[0] == 25 &&
                (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") ||
                data->payload_len[1] == 0)) {

                return true;
        }

        if (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") &&
                data->payload_len[1] == 25 &&
                (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") ||
                data->payload_len[0] == 0)) {

                return true;
        }

        return false;
}

static inline bool match_cod(lpi_data_t *data) {

        /* Presumably these are Server Info queries, except unlike the
         * Source engine above, these are only 15 bytes long */

        /* XXX: Port 28960 can be used as a distinguishing feature if we
         * start getting false positives */

        if (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") &&
                data->payload_len[0] == 15 &&
                (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") ||
                data->payload_len[1] == 0)) {

                return true;
        }

        if (MATCHSTR(data->payload[1], "\xff\xff\xff\xff") &&
                data->payload_len[1] == 15 &&
                (MATCHSTR(data->payload[0], "\xff\xff\xff\xff") ||
                data->payload_len[0] == 0)) {

                return true;
        }

        return false;
}

static inline bool match_traceroute(lpi_data_t *data) {

	/* The iVMG people put payload in their traceroute packets that
	 * we can easily identify */

	if (match_str_either(data, "iVMG"))
		return true;
	return false;

}

/* XXX Not really sure on this one - based on the code from OpenDPI but I
 * can't find any documentation that confirms this */
static inline bool match_imesh(lpi_data_t *data) {

	/* The recipient does not reply */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;
	
	/* All packets are 36 bytes */
	if (data->payload_len[0] != 36 && data->payload_len[1] != 36)
		return false;
		
	if (match_chars_either(data, 0x02, 0x00, 0x00, 0x00))
		return true;

	return false;

}

static inline bool match_halflife(lpi_data_t *data) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff))
		return false;
	if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff))
		return false;

	if (data->payload_len[0] == 20 || data->payload_len[1] == 20)
		return true;
	if (data->payload_len[1] == 9 || data->payload_len[0] == 9)
		return true;

	/*
	if (data->server_port != 27005 && data->client_port != 27005)
		return false;
	if (data->server_port != 27015 && data->client_port != 27015)
		return false;
	*/

	return false;


}

static inline bool match_other_btudp(lpi_data_t *data) {

	/* I have not been able to figure out exactly what this stuff
	 * is, but I'm pretty confident it is somehow related to a
	 * BitTorrent implementation or two */

	/* The recipient does not reply */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;
	
	if (!(match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00")))
		return false;

	if (data->payload_len[0] == 14 || data->payload_len[0] == 18)
		return true;
	if (data->payload_len[1] == 14 || data->payload_len[1] == 18)
		return true;

	return false;	

}

static inline bool match_vuze_dht_reply(lpi_data_t *data) {

	/* Each reply action is an odd number */
		
	if (match_chars_either(data, 0x00, 0x00, 0x04, 0x01))
		return true;
	if (match_chars_either(data, 0x00, 0x00, 0x04, 0x03))
		return true;
	if (match_chars_either(data, 0x00, 0x00, 0x04, 0x05))
		return true;
	if (match_chars_either(data, 0x00, 0x00, 0x04, 0x07))
		return true;

	return false;
	

}

static inline bool match_vuze_dht(lpi_data_t *data) {

	/* We can only match replies, because the requests all begin with
	 * a random connection ID. However, the connection ID must have
	 * the MSB set to 1, which will help a bit! */

	/* Let's make sure we have a reply first! */
	if (!match_vuze_dht_reply(data))
		return false;

	/* If there is no data in the opposite direction, it must be some
	 * kind of delayed or unsolicited reply (?) */
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return true;
	
	/* Otherwise, make sure the other end has an MSB set to 1 */
	if ((data->payload[0] & 0x80000000) == 0x80000000)
		return true;
	if ((data->payload[1] & 0x80000000) == 0x80000000)
		return true;
	
	return false;	
	


}

/* I *think* this is PSN game traffic - it typically appears on UDP port 3658
 * which is commonly used for that but there's no documentation of the
 * protocol anywhere :(
 */
static inline bool match_psn(lpi_data_t *data) {

	if (data->payload_len[0] == 0 &&
			MATCH(data->payload[1], 0xff, 0x83, 0xff, 0xfe))
		return true;
	if (data->payload_len[1] == 0 &&
			MATCH(data->payload[0], 0xff, 0x83, 0xff, 0xfe))
		return true;

	if (MATCH(data->payload[0], 0xff, 0x83, 0xff, 0xfe) &&
			MATCH(data->payload[1],  0xff, 0x83, 0xff, 0xfe))
		return true;

	return false;


}

static inline bool match_xlsp_payload(uint32_t payload, uint32_t len) {

	if (!MATCH(payload, 0x00, 0x00, 0x00, 0x00))
		return false;
	
	if (len == 122)
		return true;
	if (len == 156)
		return true;
	if (len == 82)
		return true;
	if (len == 0)
		return true;

	return false;

}

/* XXX Not 100% sure on this because there is little documentation, but I
 * think this is pretty close */
static inline bool match_xlsp(lpi_data_t *data) {

	/* Enforce port 3074 being involved, to reduce false positive rate for
	 * one-way transactions */
	if (data->server_port != 3074 && data->client_port != 3074)
		return false;

	if (!match_xlsp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_xlsp_payload(data->payload[1], data->payload_len[1]))
		return false;
	
	return true;

}

static inline bool match_demonware(lpi_data_t *data) {

	/* Demonware bandwidth testing involves sending a series of 1024
	 * byte packets to a known server - each packet has an incrementing
	 * seqno, starting from zero */
	
	/* The recipient does not reply */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	if (!match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00"))
		return false;

	if (data->payload_len[0] == 1024 || data->payload_len[1] == 1024)
		return true;

	/* Could also check for port 3075 if needed */

	return false;

}

static inline bool match_ntp(lpi_data_t *data) {


        /* Look for NTPv3 
         *
         * 0x1b in the first byte = v3 client
         * 0x1c in the first byte = v3 server
         * Both initial packets should be 48 bytes long, but of course the
         * server response may be missing */
        if (MATCH(data->payload[0], 0x1b, ANY, ANY, ANY) &&
                (MATCH(data->payload[1], 0x1c, ANY, ANY, ANY) ||
                data->payload_len[1] == 0) &&
                data->payload_len[0] == 48) {

                return true;
        }

        if (MATCH(data->payload[1], 0x1b, ANY, ANY, ANY) &&
                (MATCH(data->payload[0], 0x1c, ANY, ANY, ANY) ||
                data->payload_len[0] == 0) &&
                data->payload_len[1] == 48) {

                return true;
        }

        /* NTPv4 
         *
         * This time the first byte for the client is 0x23.
         * The server should response with 0x24. 
         * Packet size should remain the same */
        if (MATCH(data->payload[0], 0x23, ANY, ANY, ANY) &&
                (MATCH(data->payload[1], 0x24, ANY, ANY, ANY) ||
                data->payload_len[1] == 0) &&
                data->payload_len[0] == 48) {

                return true;
        }

        if (MATCH(data->payload[1], 0x23, ANY, ANY, ANY) &&
                (MATCH(data->payload[0], 0x24, ANY, ANY, ANY) ||
                data->payload_len[0] == 0) &&
                data->payload_len[1] == 48) {

                return true;
        }

	/* NTPv1
	 */
        if (MATCH(data->payload[0], 0x0b, ANY, ANY, ANY) &&
                (MATCH(data->payload[1], 0x0c, ANY, ANY, ANY) ||
                data->payload_len[1] == 0) &&
                data->payload_len[0] == 48) {

                return true;
        }

        if (MATCH(data->payload[1], 0x0b, ANY, ANY, ANY) &&
                (MATCH(data->payload[0], 0x0c, ANY, ANY, ANY) ||
                data->payload_len[0] == 0) &&
                data->payload_len[1] == 48) {

                return true;
        }

	/* NTPv2 */
        if (MATCH(data->payload[0], 0x13, ANY, ANY, ANY) &&
                (MATCH(data->payload[1], 0x14, ANY, ANY, ANY) ||
                data->payload_len[1] == 0) &&
                data->payload_len[0] == 48) {

                return true;
        }

        if (MATCH(data->payload[1], 0x13, ANY, ANY, ANY) &&
                (MATCH(data->payload[0], 0x14, ANY, ANY, ANY) ||
                data->payload_len[0] == 0) &&
                data->payload_len[1] == 48) {

                return true;
        }

        return false;
}

/* Matches the Opaserv worm that attacks UDP port 137
 * Ref: http://www.usenix.org/events/osdi04/tech/full_papers/singh/singh_html/
 */
static inline bool match_opaserv(lpi_data_t *data) {

	/* The recipient does not reply (usually) */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;
	
	if (data->server_port != 137 && data->client_port != 137)
		return false;

	if (match_chars_either(data, 0x01, 0x00, 0x00, 0x10))
		return true;

	return false;
}

static inline bool match_msn_video(lpi_data_t *data) {

        /* The authorization messages use a code of 0x48, followed by 3
         * bytes of zero. The packet contains no non-header payload, so the
         * payload length must be the size of the MSN video header (10 bytes)
         *
         * Ref: http://ml20rc.msnfanatic.com/vc_1_1/index.html
         */
        if (!(MATCHSTR(data->payload[0], "\x48\x00\x00\x00") &&
                        data->payload_len[0] == 10))
                return false;

        if (!(MATCHSTR(data->payload[1], "\x48\x00\x00\x00") &&
                        data->payload_len[1] == 10))
                return false;

        return true;
}



static inline bool match_ipv6(lpi_data_t *data) {

	if (match_str_both(data, "\x60\x00\x00\x00", "\x60\x00\x00\x00")) {
		return true;
	}

	if (MATCHSTR(data->payload[0], "\x60\x00\x00\x00")) {
		if (data->payload_len[1] == 0) {
			return true;
		}
	}

	if (MATCHSTR(data->payload[1], "\x60\x00\x00\x00")) {
		if (data->payload_len[0] == 0) {
			return true;
		}
	}
	return false;	
}

static inline bool match_msn_cache(lpi_data_t *data) {

	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;

	/* These packets seem to be 20 bytes */
	if (data->payload_len[0] != 20 && data->payload_len[1] != 20)
		return false;

	if (match_chars_either(data, 0x02, 0x04, 0x00, 0x00))
		return true;

	return false;

}

static bool match_stun_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return false;
	
	/* Bytes 3 and 4 are the Message Length - the STUN header 
	 *
	 * XXX Byte ordering is a cock! */
	if ((ntohl(payload) & 0x0000ffff) != len - 20)
		return false;
	
	if (MATCH(payload, 0x00, 0x01, ANY, ANY))
		return true;
	if (MATCH(payload, 0x01, 0x01, ANY, ANY))
		return true;

	return false;

}

static inline bool match_stun(lpi_data_t *data) {

	/* This seems to be a special response containing a STUN token
	 *
	 * Not very well-documented though :(
	 */

	if (match_str_either(data, "RSP/"))
		return true;

	if (match_stun_payload(data->payload[0], data->payload_len[0]))
		return true;
	if (match_stun_payload(data->payload[1], data->payload_len[1]))
		return true;

	return false;


}

static bool match_teredo_payload(uint32_t payload, uint32_t len) {
	
	if (len == 0)
		return true;
	if (!MATCH(payload, 0x00, 0x01, 0x00, 0x00))
		return false;

	if (len == 61 || len == 109 || len == 77)
		return true;
	
	return false;
	
}

static inline bool match_teredo(lpi_data_t *data) {

	if (data->server_port != 3544 && data->client_port != 3544)
		return false;
	
	if (!match_teredo_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_teredo_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;

}

static inline bool match_diablo2(lpi_data_t *data) {

	if (data->server_port != 6112 && data->client_port != 6112)
		return false;
	
	if (data->payload_len[0] != 0 && data->payload_len[0] != 8)
		return false;
	if (data->payload_len[1] != 0 && data->payload_len[1] != 8)
		return false;

	if (data->payload_len[0] == 8) {
		if (!MATCH(data->payload[0], 0x03, 0x00, 0x00, 0x00))
			return false;
	}
	if (data->payload_len[1] == 8) {
		if (!MATCH(data->payload[1], 0x03, 0x00, 0x00, 0x00))
			return false;
	}

	return true;
}

static inline bool match_sip(lpi_data_t *data) {

        if (match_chars_either(data, 'S', 'I', 'P', ANY))
		return true;
	
	if (match_str_either(data, "OPTI") && 
			(data->payload_len[0] == 0 || 
			data->payload_len[1] == 0))
		return true;

	return false;
	
}

/* This seems to be a Pando thing - I've found libtorrent handshakes within
 * full payload captures of these packets that refer to Pando peer exchange.
 *
 * It may be a wider Bittorrent thing, but I haven't found any evidence to
 * suggest that any clients other than Pando use it */
static inline bool match_pando_udp(lpi_data_t *data) {

	if (match_str_both(data, "\x00\x00\x00\x09", "\x00\x00\x00\x09"))
		return true;
	
	if (MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x09) &&
			data->payload_len[1] == 0)
		return true;

	if (MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x09) &&
			data->payload_len[0] == 0)
		return true;

	return false;
}

static inline bool match_kad(uint32_t payload, uint32_t len) {

	if (MATCH(payload, 0xe4, 0x21, ANY, ANY) && len == 35) 
		return true;
	if (MATCH(payload, 0xe4, 0x4b, ANY, ANY) && len == 19) 
		return true;
	if (MATCH(payload, 0xe4, 0x11, ANY, ANY)) {
		if (len == 22 || len == 38 || len == 28) 
			return true;
	}

	if (MATCH(payload, 0xe4, 0x19, ANY, ANY)) {
		if (len == 22 || len == 38 || len == 28) 
			return true;
	}


	if (MATCH(payload, 0xe4, 0x20, ANY, ANY) && len == 35) 
		return true;
	
	if (MATCH(payload, 0xe4, 0x18, ANY, ANY) && len == 27)
		return true;
	
	if (MATCH(payload, 0xe4, 0x10, ANY, ANY) && len == 27)
		return true; 
	
	if (MATCH(payload, 0xe4, 0x58, ANY, ANY) && len == 6)
		return true;
	
	if (MATCH(payload, 0xe4, 0x50, ANY, ANY) && len == 4)
		return true;	
	
	if (MATCH(payload, 0xe4, 0x29, ANY, ANY)) {
		if (len == 119 || len == 69 || len == 294) 
			return true;
	}
	
	if (MATCH(payload, 0xe4, 0x28, ANY, ANY)) {
		if (len == 119 || len == 69 || len == 294) 
			return true;
	}
	
	return false;

}

static bool is_emule_udp(uint32_t payload, uint32_t len) {
	
	/* Mainly looking at Kad stuff here - Kad packets start with 0xe4
	 * for uncompressed and 0xe5 for compressed data */


	/* Compressed stuff seems to always begin the same */
	if (MATCH(payload, 0xe5, 0x43, ANY, ANY))
		return true;

	/* emule extensions */
	if (MATCH(payload, 0xc5, 0x90, ANY, ANY) && (len < 100))
		return true;
	if (MATCH(payload, 0xc5, 0x91, ANY, ANY) && (len == 6 || len == 16))
		return true;
	if (MATCH(payload, 0xc5, 0x92, ANY, ANY) && (len == 2))
		return true;
	if (MATCH(payload, 0xc5, 0x93, ANY, ANY) && (len == 2))
		return true;

	/* 0xe3 covers conventional emule messages */
	if (MATCH(payload, 0xe3, 0x9a, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe3, 0x9b, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe3, 0x96, ANY, ANY) && len == 6)
		return true;
	
	if (MATCH(payload, 0xe3, 0x97, ANY, ANY)) {
		if (len <= 34 && ((len - 2) % 4 == 0))
			return true;
	}
	
	if (MATCH(payload, 0xe3, 0x92, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe3, 0x98, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe3, 0x99, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe3, 0xa2, ANY, ANY) && len == 6)
		return true;
	if (MATCH(payload, 0xe3, 0xa3, ANY, ANY))
		return true;



	
	if (match_kad(payload, len))
		return true;

	
	return false;	

}

static bool match_emule_udp(lpi_data_t *data) {


	if (data->payload_len[0] == 0 && 
			is_emule_udp(data->payload[1], data->payload_len[1])) {
		return true;
	}

	if (data->payload_len[1] == 0 && 
			is_emule_udp(data->payload[0], data->payload_len[0])) {
		return true;
	}

	if (is_emule_udp(data->payload[0], data->payload_len[0]) &&
			is_emule_udp(data->payload[1], data->payload_len[1]))
		return true;

	return false;

}

static bool is_kad_e9_payload(uint32_t payload, uint32_t len) {
	
	/* This seem to be some variant of Kademlia, although I have not
	 * been able to figure out which */

	/* All packets begin with e9, while possible second bytes are 
	 * 0x55, 0x56, 0x60, 0x61, 0x76, 0x75
	 *
	 * 0x56 is a response to 0x55
	 * 0x61 is a response to 0x60
	 * 0x76 is a kind of FIN packet, it also responds to 0x75
	 *
	 * There are also packets that seem to begin with 0xea 0x75 0x78 0x9c.
	 */

	if (MATCH(payload, 0xe9, 0x55, ANY, ANY) && len == 27)
		return true;
	if (MATCH(payload, 0xe9, 0x56, ANY, ANY) && len == 27)
		return true;
	if (MATCH(payload, 0xe9, 0x60, ANY, ANY) && len == 34)
		return true;
	if (MATCH(payload, 0xe9, 0x61, ANY, ANY))
		return true;
	if (MATCH(payload, 0xe9, 0x76, ANY, ANY) && len == 18)
		return true;
	if (MATCH(payload, 0xe9, 0x75, ANY, ANY))
		return true;
	
	
	if (MATCH(payload, 0xea, 0x75, 0x78, 0x9c))
		return true;
	
	return false;	

}

static inline bool match_kademlia_udp(lpi_data_t *data) {

	if (data->payload_len[0] == 0 && is_kad_e9_payload(data->payload[1], 
				data->payload_len[1]))
		return true;
	
	if (data->payload_len[1] == 0 && is_kad_e9_payload(data->payload[0], 
				data->payload_len[0]))
		return true;

	if (is_kad_e9_payload(data->payload[0], data->payload_len[0]) &&
			is_kad_e9_payload(data->payload[1], 
			data->payload_len[1]))
		return true;

	return false;
}


lpi_protocol_t guess_udp_protocol(lpi_data_t *proto_d) {

	if (proto_d->payload_len[0] < 4 && proto_d->payload_len[1] < 4)
		return LPI_PROTO_NO_PAYLOAD;


        if (match_sip(proto_d))
                return LPI_PROTO_UDP_SIP;

	/* XXX May want to separate Vuze DHT from the other DHT at some point */
        if (match_chars_either(proto_d, 'd', '1', ':', ANY))
                return LPI_PROTO_UDP_BTDHT;
	if (match_vuze_dht(proto_d)) return LPI_PROTO_UDP_BTDHT;
	if (match_xbt_tracker(proto_d)) return LPI_PROTO_UDP_BTDHT;


        if (match_chars_either(proto_d, 0x01, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

        if (match_chars_either(proto_d, 0x02, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

	if (match_traceroute(proto_d)) return LPI_PROTO_UDP_TRACEROUTE;

        if (match_steam(proto_d)) return LPI_PROTO_UDP_STEAM;

        if (match_cod(proto_d)) return LPI_PROTO_UDP_COD;

	if (match_stun(proto_d)) return LPI_PROTO_UDP_STUN;

        /*
        if (match_str_both(proto_d, "\xff\xff\xff\xff", "\xff\xff\xff\xff"))
                return LPI_PROTO_UDP_QUAKEWORLD;
        */

        if (match_chars_either(proto_d, 'G', 'N', 'D', ANY))
                return LPI_PROTO_UDP_GNUTELLA;
	if (match_gnutella_oob(proto_d))
                return LPI_PROTO_UDP_GNUTELLA;
	if (match_gnutella(proto_d))
		return LPI_PROTO_UDP_GNUTELLA;

        if (match_str_both(proto_d, "\x32\x00\x00\x00", "\x32\x00\x00\x00"))
                return LPI_PROTO_XUNLEI;
	if (match_str_either(proto_d, "\x32\x00\x00\x00") && 	
			(proto_d->payload_len[0] == 0 || 
			proto_d->payload_len[1] == 0))
		return LPI_PROTO_XUNLEI;

	if (match_opaserv(proto_d)) return LPI_PROTO_UDP_OPASERV;

	if (match_mp2p(proto_d)) return LPI_PROTO_UDP_MP2P;

        if (match_str_either(proto_d, "VS01"))
                return LPI_PROTO_UDP_STEAM_FRIENDS;

	if (match_str_either(proto_d, "DISC")) 
		return LPI_PROTO_UDP_SPAMFIGHTER;
	if (match_str_either(proto_d, "SCP\x03")) 
		return LPI_PROTO_UDP_SPAMFIGHTER;


        if (match_str_either(proto_d, "EYE1"))
                return LPI_PROTO_UDP_EYE;

	if (match_messenger_spam(proto_d))
		return LPI_PROTO_UDP_WIN_MESSAGE;

	if (match_rtp(proto_d))
                return LPI_PROTO_UDP_RTP;

	if (match_chars_either(proto_d, 0x40, 0x00, 0x00, 0x00))
		return LPI_PROTO_UDP_SECONDLIFE;

	if (match_sql_worm(proto_d)) return LPI_PROTO_UDP_SQLEXP;

	if (match_xlsp(proto_d)) return LPI_PROTO_UDP_XLSP;

	if (match_demonware(proto_d)) return LPI_PROTO_UDP_DEMONWARE;

	if (match_halflife(proto_d)) return LPI_PROTO_UDP_HL;

        if (match_msn_video(proto_d)) return LPI_PROTO_UDP_MSN_VIDEO;

	if (match_msn_cache(proto_d)) return LPI_PROTO_UDP_MSN_CACHE;

        if (match_ntp(proto_d)) return LPI_PROTO_UDP_NTP;

	if (match_ipv6(proto_d)) return LPI_PROTO_UDP_IPV6;
	
	if (match_imesh(proto_d)) return LPI_PROTO_UDP_IMESH;

	if (match_diablo2(proto_d)) return LPI_PROTO_UDP_DIABLO2;

	if (match_orbit(proto_d)) return LPI_PROTO_UDP_ORBIT;

	if (match_teredo(proto_d)) return LPI_PROTO_UDP_TEREDO;

	if (match_psn(proto_d)) return LPI_PROTO_UDP_PSN;

	/* Not sure what exactly this is, but I'm pretty sure it is related to
	 * BitTorrent */
	if (match_other_btudp(proto_d)) return LPI_PROTO_UDP_BTDHT;
        
	if (match_dns(proto_d))
                return LPI_PROTO_UDP_DNS;

	if (match_pando_udp(proto_d))
		return LPI_PROTO_UDP_PANDO;

	if (match_kademlia_udp(proto_d))
		return LPI_PROTO_UDP_KADEMLIA;

        if (match_emule_udp(proto_d))
		return LPI_PROTO_UDP_EMULE;
	if (match_emule(proto_d))
                return LPI_PROTO_UDP_EMULE;

	if (match_esp_encap(proto_d)) return LPI_PROTO_UDP_ESP;

	/* XXX Starcraft seems to set the first four bytes of every packet to 00 00 00 00,
	 * but we probably need something else to identify it properly */

        return LPI_PROTO_UDP;
}


