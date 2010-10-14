
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
	/* I'm still a touch uncertain about this one - almost all the 
	 * examples appear on port 41170 (which is the MP2P port), but the
	 * first four bytes are supposed to be a checksum. In theory, this
	 * should differ a lot more than it does, which is where my 
	 * uncertainty comes from. 
	 *
	 * It is possible that they reworked the protocol, or the checksum is
	 * poorly calculated, I guess.
	 */

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

	/* This occurs one-way only */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	/* The UDP communication begins with all zeroes */
	if (!match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00"))
		return false;
	
	if (data->payload_len[0] == 23 || data->payload_len[1] == 23)
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

static inline bool match_halflife(lpi_data_t *data) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff))
		return false;
	if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff))
		return false;

	if (data->payload_len[0] == 20 || data->payload_len[1] == 20)
		return true;

	/*
	if (data->server_port != 27005 && data->client_port != 27005)
		return false;
	if (data->server_port != 27015 && data->client_port != 27015)
		return false;
	*/

	return false;


}

/* XXX Not 100% sure on this because there is little documentation, but I
 * think this is pretty close */
static inline bool match_xlsp(lpi_data_t *data) {

	if (!match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00"))
		return false;
	
	if (data->payload_len[0] == 122 && data->payload_len[1] == 156)
		return true;
	
	if (data->payload_len[1] == 122 && data->payload_len[0] == 156)
		return true;
	
	if (data->payload_len[0] == 82 && data->payload_len[1] == 122)
		return true;
	
	if (data->payload_len[1] == 122 && data->payload_len[0] == 82)
		return true;

	if (data->payload_len[0] == 82 && data->payload_len[1] == 0)
		return true;
	
	if (data->payload_len[1] == 0 && data->payload_len[0] == 82)
		return true;
	
	if (data->payload_len[0] == 156 && data->payload_len[1] == 0)
		return true;
	
	if (data->payload_len[1] == 0 && data->payload_len[0] == 156)
		return true;
	/* Could also check for port 3074 if we're having false positive
	 * problems */
	return false;
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

lpi_protocol_t guess_udp_protocol(lpi_data_t *proto_d) {

	if (proto_d->payload_len[0] < 4 && proto_d->payload_len[1] < 4)
		return LPI_PROTO_NO_PAYLOAD;


        if (match_chars_either(proto_d, 'S', 'I', 'P', ANY))
                return LPI_PROTO_UDP_SIP;

        if (match_chars_either(proto_d, 'd', '1', ':', ANY))
                return LPI_PROTO_UDP_BTDHT;

        if (match_chars_either(proto_d, 0x01, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

        if (match_chars_either(proto_d, 0x02, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

	if (match_traceroute(proto_d)) return LPI_PROTO_UDP_TRACEROUTE;

        if (match_steam(proto_d)) return LPI_PROTO_UDP_STEAM;

        if (match_cod(proto_d)) return LPI_PROTO_UDP_COD;

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

        if (match_chars_either(proto_d, 0x80, 0x80, ANY, ANY) &&
                        match_str_either(proto_d, "\x00\x01\x00\x08"))
                return LPI_PROTO_UDP_RTP;

	if (match_chars_either(proto_d, 0x40, 0x00, 0x00, 0x00))
		return LPI_PROTO_UDP_SECONDLIFE;

	if (match_xlsp(proto_d)) return LPI_PROTO_UDP_XLSP;

	if (match_demonware(proto_d)) return LPI_PROTO_UDP_DEMONWARE;

	if (match_halflife(proto_d)) return LPI_PROTO_UDP_HL;

        if (match_msn_video(proto_d)) return LPI_PROTO_UDP_MSN_VIDEO;

        if (match_ntp(proto_d)) return LPI_PROTO_UDP_NTP;

        if (match_dns(proto_d))
                return LPI_PROTO_UDP_DNS;

        if (match_emule(proto_d))
                return LPI_PROTO_UDP_EMULE;

	/* XXX Starcraft seems to set the first four bytes of every packet to 00 00 00 00,
	 * but we probably need something else to identify it properly */

        return LPI_PROTO_UDP;
}


