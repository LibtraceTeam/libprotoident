
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

	/* Gamespy request begins with 0xfe 0xfd FOO BAR. The response begins
	 * with FOO BAR, where FOO and BAR are specific bytes */

        if (MATCH(data->payload[0], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[1] << 16) == (data->payload[0] & 0xffff0000)))
                return true;
        if (MATCH(data->payload[1], 0xfe, 0xfd, ANY, ANY) &&
                ((data->payload[0] << 16) == (data->payload[1] & 0xffff0000)))
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
	if (match_chars_either(data, ANY, 0x4b, 0xd9, 0x65))
		return true;
	if (match_chars_either(data, ANY, 0x4a, 0xd9, 0x65))
		return true;
	if (match_chars_either(data, ANY, 0x4a, 0xd6, 0x6f))
		return true;


	/* Seeing a lot of these in flows using port 41170 both ways */
	if (MATCH(data->payload[0], ANY, ANY, 0x00, 0x00)) {
		if (data->payload_len[1] != 0)
			return false;
		if (data->payload_len[0] == 242)
			return true;
		if (data->payload_len[0] == 240)
			return true;
	}

	if (MATCH(data->payload[1], ANY, ANY, 0x00, 0x00)) {
		if (data->payload_len[0] != 0)
			return false;
		if (data->payload_len[1] == 242)
			return true;
		if (data->payload_len[1] == 240)
			return true;
	}
	return false;
	
}		

static inline bool match_freechal(lpi_data_t *data) {

	if (match_str_both(data, "GET ", "FCP2"))
		return true;
	return false;

}

static inline bool match_netbios_req(uint32_t payload, uint32_t len) {

	if (MATCH(payload, 0x80, 0xb0, 0x00, 0x00)) {
		if (len == 50)
			return true;
		if (len == 20)
			return true;
	}

	if (MATCH(payload, 0x80, 0x94, 0x00, 0x00)) {
		if (len == 50)
			return true;
	}
	return false;

}

static inline bool match_netbios(lpi_data_t *data) {

	/* Haven't yet seen an actual response to Netbios lookups */

	if (match_netbios_req(data->payload[0], data->payload_len[0])) {
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_netbios_req(data->payload[1], data->payload_len[1])) {
		if (data->payload_len[0] == 0)
			return true;
	}

	return false;

}

static inline bool match_quake_ping(lpi_data_t *data) {

	/* The client appears to send a "ping" (which is not part of the
	 * documented Quake engine protocol). The server responds with a
	 * standard "ffffffff" packet */

	if (MATCHSTR(data->payload[0], "ping") && data->payload_len[0] == 4) {
		if (data->payload_len[1] == 0)
			return true;
		if (data->payload_len[1] != 14)
			return false;
		if (MATCHSTR(data->payload[1], "\xff\xff\xff\xff"))
			return true;
		return false;
	}

	if (MATCHSTR(data->payload[1], "ping") && data->payload_len[1] == 4) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[0] != 14)
			return false;
		if (MATCHSTR(data->payload[0], "\xff\xff\xff\xff"))
			return true;
		return false;
	}

	return false;
}

static inline bool match_quake(lpi_data_t *data) {

	/* Trying to match generic Quake engine games - typically use port 
	 * 27960 */

	if (match_quake_ping(data))
		return true;

	if (!match_str_both(data, "\xff\xff\xff\xff", "\xff\xff\xff\xff"))
		return false;
	if (data->payload_len[0] == 16) {
		if (data->payload_len[1] >= 51 && data->payload_len[1] <= 54)
			return true;
	}
	if (data->payload_len[1] == 16) {
		if (data->payload_len[0] >= 51 && data->payload_len[0] <= 54)
			return true;
	}

	return false;
}

static inline bool match_gta4(lpi_data_t *data) {

	if (match_str_both(data, "\xfd\xfc\x1e\x66", "\xfd\xfc\x1e\x66"))
		return true;

	if (match_str_either(data, "\xfd\xfc\x1e\x66")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	return false;

}

static inline bool match_rtp(lpi_data_t *data) {
        if (match_chars_either(data, 0x80, 0x80, ANY, ANY) &&
                        match_str_either(data, "\x00\x01\x00\x08"))
		return true;
	
	/* 96 and 97 are the first two dynamic payload types */
	if (match_chars_either(data, 0x80, 0x60, ANY, ANY) && 
			(data->payload_len[0] == 0 || data->payload_len[1]==0))
		return true;
	if (match_chars_either(data, 0x80, 0x61, ANY, ANY) && 
			(data->payload_len[0] == 0 || data->payload_len[1]==0))
		return true;

	
	/* If the MSB in the second byte is set, this is a "marker" packet */
	if (match_chars_either(data, 0x80, 0xe0, ANY, ANY) && 
			(data->payload_len[0] == 0 || data->payload_len[1]==0))
		return true;
	if (match_chars_either(data, 0x80, 0xe1, ANY, ANY) && 
			(data->payload_len[0] == 0 || data->payload_len[1]==0))
		return true;

	return false;

}

static inline bool match_pplive(lpi_data_t *data) {

	if (match_str_both(data, "\xe9\x03\x41\x01", "\xe9\x03\x42\x01"))
		return true;
	if (match_str_either(data, "\xe9\x03\x41\x01")) {
		if (data->payload_len[0] == 0 && data->payload_len[1] == 57)
			return true;
		if (data->payload_len[1] == 0 && data->payload_len[0] == 57)
			return true;
	}
	return false;
}

static inline bool match_checkpoint_rdp(lpi_data_t *data) {

	/* We only see this on port 259, so I'm pretty sure that this is
	 * the Checkpoint proprietary RDP protocol (not to be confused with
	 * Remote Desktop Protocol or the RDP transport protocol).
	 *
	 * Begins with a four byte magic number */

	if (match_str_both(data, "\xf0\x01\xcc\xcc", "\xf0\x01\xcc\xcc"))
		return true;
	if (match_str_either(data, "\xf0\x01\xcc\xcc")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	
	return false;	

}

static inline bool match_teamspeak(lpi_data_t *data) {

	/* Teamspeak version 2 */
	if (match_str_both(data, "\xf4\xbe\x03\x00", "\xf4\xbe\x03\x00"))
		return true;
	return false;

}

static inline bool match_ipmsg(lpi_data_t *data) {

	/* IPMSG packet format:
	 *
	 * Version:MessageNumber:User:Host:Command:MsgContent
	 *
	 * Version is always 1.
	 *
	 * All IPMsg observed so far has a message number beginning with
	 * 80...
	 */

	/* Do a port check as well, just to be sure */
	if (data->server_port != 2425 && data->client_port != 2425)
		return false;

	if (match_chars_either(data, '1', ':', '8', '0'))
		return true;

	return true;

}

static inline bool match_qq(lpi_data_t *data) {

	if (match_str_both(data, "\x02\x01\x00\x00", "\x02\x01\x00\x00")) {
		if (data->payload_len[0] == 75 && data->payload_len[1] == 43)
			return true;
	
		if (data->payload_len[1] == 75 && data->payload_len[0] == 43)
			return true;
	}

	if (match_str_both(data, "\x02\x02\x00\x00", "\x02\x02\x00\x00")) {
		if (data->payload_len[0] == 83 && data->payload_len[1] == 43)
			return true;
	
		if (data->payload_len[1] == 83 && data->payload_len[0] == 43)
			return true;
	}
	return false;
}

static inline bool match_eso_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len == 40 && MATCH(payload, 0x00, ANY, ANY, ANY))
		return true;
	if (len == 10 && MATCH(payload, 0x07, 0xa9, 0x00, 0x00))
		return true;

	return false;

}

static inline bool match_eso(lpi_data_t *data) {

	/* I'm pretty sure this is Ensemble game traffic, as it is the
	 * only thing I can find matching the port 2300 that it commonly
	 * occurs on. No game docs available, though :( */

	if (!match_eso_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_eso_payload(data->payload[1], data->payload_len[1]))
		return false;
	return true;

}

static inline bool match_rdt(lpi_data_t *data) {

	/* The Real Data Transport is not explicitly documented in full,
	 * but these packets seem to resemble those examples we have been able
	 * to find.
	 *
	 * https://protocol.helixcommunity.org/2005/devdocs/RDT_Feature_Level_30.txt
	 */

	if (!match_str_both(data, "\x00\xff\x03\x00", "\x00\xff\x04\x49"))
		return false;

	if (data->payload_len[0] == 3 && data->payload_len[1] == 11)
		return true;
	if (data->payload_len[1] == 3 && data->payload_len[0] == 11)
		return true;

	return false;
}

static inline bool match_slp_req(uint32_t payload, uint32_t len) {

	/* According to RFC 2608, the 3rd and 4th bytes should be the 
	 * length (including the SLP header). This doesn't appear to be the
	 * case with any of the port 427 traffic I've seen, so either I'm
	 * wrong or people fail at following RFCs */
	
	if (MATCH(payload, 0x02, 0x01, 0x00, 0x00) && len == 49) {
		return true;
	}

	return false;

}

static inline bool match_slp_resp(uint32_t payload, uint32_t len) {

	/* I haven't actually observed any responses yet, so just going
	 * on what the spec says :/ */
	
	if (len == 0)
		return true;

	if (MATCH(payload, 0x02, 0x02, ANY, ANY)) {
		return true;
	}

	return false;
}

static inline bool match_slp(lpi_data_t *data) {

	if (data->server_port != 427 && data->client_port != 427)
		return false;

	if (match_slp_req(data->payload[0], data->payload_len[0])) {
		if (match_slp_resp(data->payload[1], data->payload_len[1]))
			return true;
		return false;
	}

	if (match_slp_req(data->payload[1], data->payload_len[1])) {
		if (match_slp_resp(data->payload[0], data->payload_len[0]))
			return true;
		return false;
	}

	return false;
}

static inline bool match_directconnect(lpi_data_t *data) {
	
	if (data->payload_len[0] == 0 && 
			MATCHSTR(data->payload[1], "$SR "))
		return true;
	if (data->payload_len[1] == 0 && 
			MATCHSTR(data->payload[0], "$SR "))
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
	
	/* If only one port is 4500, check for the Non-ESP marker */
	if (data->server_port == 4500 || data->client_port == 4500) {
		if (data->payload[0] == 0 && data->payload[1] == 0)
			return true;
	}

	return false;

}

static inline bool match_isakmp(lpi_data_t *data) {

	/* Rule out anything not on UDP port 500 */
	if (data->server_port != 500 && data->client_port != 500)
		return false;

	/* First four bytes are the cookie for the initiator, so should match 
	 * in both directions */

	if (data->payload[0] != data->payload[1])
		return false;
	if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
		return false;

	return true;
}

static inline bool match_orbit_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (MATCH(payload, 0xaa, 0x20, 0x04, 0x04) && len == 36)
		return true;
	if (MATCH(payload, 0xaa, 0x10, ANY, ANY) && len == 27)
		return true;
	if (MATCH(payload, 0xaa, 0x18, ANY, ANY) && len == 27)
		return true;
	if (MATCH(payload, 0xab, 0x08, 0x78, 0xda))
		return true;


}

static inline bool match_orbit(lpi_data_t *data) {

	/* There's no nice spec for the Orbit UDP protocol, so I'm just
	 * going to match based on evidence observed thus far */

	if (data->server_port != 20129 && data->client_port != 20129)
		return false;

	if (!match_orbit_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_orbit_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;	
}

static inline bool match_kazaa(lpi_data_t *data) {

	/* 0x27 is a ping, 0x28 and 0x29 are pongs */

	/* A Kazaa ping is usually 12 bytes, 0x28 pong is 17, 0x29 pong is 21 */

	if (match_str_both(data, "\x27\x00\x00\x00", "\x28\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x27\x00\x00\x00", "\x29\x00\x00\x00"))
		return true;

	if (match_str_either(data, "\x27\x00\x00\x00")) {
		if (data->payload_len[0] == 0 && data->payload_len[1] == 12)
			return true;
		if (data->payload_len[1] == 0 && data->payload_len[0] == 12)
			return true;
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

static inline bool match_norton(lpi_data_t *data) {

	if (MATCH(data->payload[0], 0x02, 0x0a, 0x00, 0xc0)) {
		if (data->payload_len[0] != 16)
			return false;
		if (data->payload_len[1] != 0)
			return false;
		return true;
	}
	if (MATCH(data->payload[1], 0x02, 0x0a, 0x00, 0xc0)) {
		if (data->payload_len[1] != 16)
			return false;
		if (data->payload_len[0] != 0)
			return false;
		return true;
	}
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
	if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
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


	/* All Gnutella UDP communications begin with a random 16 byte
	 * message ID - the request and the response must have the same
	 * message ID */

	/* OK, for now I'm going to just work with two-way exchanges, because
	 * one-way is going to be pretty unreliable :( */

	/* One exception! Unanswered PINGs */
	if (data->payload_len[0] == 23 && data->payload_len[1] == 0)
		return true;
	if (data->payload_len[1] == 23 && data->payload_len[0] == 0)
		return true;

	if (data->payload_len[1] == 0 || data->payload_len[0] == 0)
		return false;

	/* There seem to be some message types that do weird stuff with the
	 * GUID - I suspect they are Limewire extensions. */

	if (data->payload_len[0] == 23 && data->payload_len[1] == 23) {
		if (match_chars_either(data, 0x00, 0x00, 0x00, 0x00))
			return true;
	}

	/* If there is payload in both directions, the message IDs must match */
	if (data->payload[0] != data->payload[1])
		return false;


	/* All of these payload combinations are based purely on transactions
	 * observed on UDP port 6346 (a known Gnutella port) - sadly, there's
	 * no genuinely good documentation on the typical size of Gnutella
	 * UDP requests */
	
	/* PING */
	if (data->payload_len[0] == 23 && data->payload_len[1] < 100)
		return true;
	if (data->payload_len[1] == 23 && data->payload_len[0] < 100)
		return true;
	
	/* 727 byte packets are matched with 81 or 86 byte packets */
	if (data->payload_len[0] == 727 && (data->payload_len[1] == 81 ||
			data->payload_len[1] == 86))
		return true;
	if (data->payload_len[1] == 727 && (data->payload_len[0] == 81 ||
			data->payload_len[0] == 86))
		return true;

	/* 72 and (61 or 81 or 86) byte packets seem to go together */
	if (data->payload_len[0] == 72) {
		if (data->payload_len[1] == 61)
			return true;
		if (data->payload_len[1] == 81)
			return true;
		if (data->payload_len[1] == 86)
			return true;
	}

	if (data->payload_len[1] == 72) {
		if (data->payload_len[0] == 61)
			return true;
		if (data->payload_len[0] == 81)
			return true;
		if (data->payload_len[0] == 86)
			return true;
	}

	/* 81 and 544 */
	if (data->payload_len[0] == 81 && data->payload_len[1] == 544)
		return true;
	if (data->payload_len[1] == 81 && data->payload_len[0] == 544)
		return true;

	/* 55 and 47 */
	if (data->payload_len[0] == 55 && data->payload_len[1] == 47)
		return true;
	if (data->payload_len[1] == 55 && data->payload_len[0] == 47)
		return true;

	/* 38 and 96 */
	if (data->payload_len[0] == 38 && data->payload_len[1] == 96)
		return true;
	if (data->payload_len[1] == 38 && data->payload_len[0] == 96)
		return true;

	/* 67 and (81 or 86) */
	if (data->payload_len[0] == 67 && (data->payload_len[1] == 81 ||
			data->payload_len[1] == 86))
		return true;
	if (data->payload_len[1] == 67 && (data->payload_len[0] == 81 ||
			data->payload_len[0] == 86))
		return true;


	/* Responses to 35 byte requests range between 136 and 180 bytes */
	if (data->payload_len[0] == 35 && (data->payload_len[1] <= 180 &&
			data->payload_len[1] >= 136))
		return true;
	if (data->payload_len[1] == 35 && (data->payload_len[0] <= 180 &&
			data->payload_len[0] >= 136))
		return true;

	/* 29 byte requests seem to be met with 80-100 byte responses OR
	 * a 46 byte response */
	if (data->payload_len[0] == 29) {
		if (data->payload_len[1] <= 100 && data->payload_len[1] >= 80)
			return true;
		if (data->payload_len[1] == 46)
			return true;
	}
	if (data->payload_len[1] == 29) {
		if (data->payload_len[0] <= 100 && data->payload_len[0] >= 80)
			return true;
		if (data->payload_len[0] == 46)
			return true;
	}

	/* 34 byte requests seem to be met with 138-165 byte responses */
	if (data->payload_len[0] == 34 && (data->payload_len[1] <= 165 &&
			data->payload_len[1] >= 138))
		return true;
	if (data->payload_len[1] == 34 && (data->payload_len[0] <= 165 &&
			data->payload_len[0] >= 138))
		return true;
	
	/* 86 byte requests seem to be met with 100-225 byte responses */
	if (data->payload_len[0] == 86 && (data->payload_len[1] <= 225 &&
			data->payload_len[1] >= 100))
		return true;
	if (data->payload_len[1] == 86 && (data->payload_len[0] <= 225 &&
			data->payload_len[0] >= 100))
		return true;

	/* 193 matches 108 or 111 */
	if (data->payload_len[0] == 193 && (data->payload_len[1] == 108 ||
			data->payload_len[1] == 111))
		return true;
	if (data->payload_len[1] == 193 && (data->payload_len[0] == 108 ||
			data->payload_len[0] == 111))
		return true;

	/* The response to 73 bytes tends to vary in size */
	if (data->payload_len[0] == 73)
		return true;
	if (data->payload_len[1] == 73)
		return true;

	/* The response to 96 bytes tends to vary in size */
	if (data->payload_len[0] == 96)
		return true;
	if (data->payload_len[1] == 96)
		return true;
	
	/* The response to 28 bytes tends to vary in size, but is less than 
	 * 200 */
	if (data->payload_len[0] == 28 && data->payload_len[1] < 200)
		return true;
	if (data->payload_len[1] == 28 && data->payload_len[0] < 200)
		return true;
	
	/* Same for 31 bytes */
	if (data->payload_len[0] == 31 && data->payload_len[1] < 200)
		return true;
	if (data->payload_len[1] == 31 && data->payload_len[0] < 200)
		return true;
	
	return false;	
	

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

static inline bool match_ase_ping(lpi_data_t *data) {

	/* Commonly used by MultiTheftAuto - the use of "ping" and
	 * "Ping" is not documented though */

	if (MATCHSTR(data->payload[0], "ping")) {
		if (data->payload_len[0] != 16)
			return false;
		if (data->payload_len[1] == 0)
			return true;
		if (data->payload_len[1] != 16)
			return false;
		if (MATCHSTR(data->payload[1], "Ping"))
			return true;
		return false;
	}
	
	if (MATCHSTR(data->payload[1], "ping")) {
		if (data->payload_len[1] != 16)
			return false;
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[0] != 16)
			return false;
		if (MATCHSTR(data->payload[0], "Ping"))
			return true;
		return false;
	}
	
	return false;

}

static inline bool match_jedi_academy(lpi_data_t *data) {

	/* Pretty rare, but we can write a rule for it */
	if (match_str_both(data, "\xff\xff\xff\xff", "\xff\xff\xff\xff")) {
		/* Server browsing */
		if (data->payload_len[0] == 65 && data->payload_len[1] == 181)
			return true;
		if (data->payload_len[0] == 66 && data->payload_len[1] == 182)
			return true;
		if (data->payload_len[1] == 65 && data->payload_len[0] == 181)
			return true;
		if (data->payload_len[1] == 66 && data->payload_len[0] == 182)
			return true;

		/* Actual gameplay */
		if (data->payload_len[0] == 16 && data->payload_len[1] == 32)
			return true;
		if (data->payload_len[1] == 16 && data->payload_len[0] == 32)
			return true;
	}

	return false;

}

static inline bool match_cod_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (!MATCH(payload, 0xff, 0xff, 0xff, 0xff))
		return false;
	return true;

}

static inline bool match_cod(lpi_data_t *data) {

	if (!match_cod_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_cod_payload(data->payload[1], data->payload_len[1]))
		return false;

	/* One packet is always 14 or 15 bytes, the other is usually much 
	 * larger */
	if (data->payload_len[0] == 14 || data->payload_len[0] == 15) {
		if (data->payload_len[1] == 0)
			return true;
		if (data->payload_len[1] > 100)
			return true;
	}

	if (data->payload_len[1] == 14 || data->payload_len[1] == 15) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[0] > 100)
			return true;
	}

	/* 13 is also observed */
	if (data->payload_len[0] == 13) {
		if (data->payload_len[1] > 880)
			return true;
	}

	/* Other packet size combos */

	/* 74 seems to be common on port 20800 which is associated with
	 * COD:WaW
	 */
	if (data->payload_len[0] == 74) {
		if (data->payload_len[1] == 0)
			return true;
	}
	
	if (data->payload_len[1] == 74) {
		if (data->payload_len[0] == 0)
			return true;
	}

	if (data->payload_len[0] == 45) {
		if (data->payload_len[1] == 0)
			return true;
	}
	
	if (data->payload_len[1] == 45) {
		if (data->payload_len[0] == 0)
			return true;
	}

	if (data->payload_len[0] == 53) {
		if (data->payload_len[1] < 30)
			return false;
		if (data->payload_len[1] > 33)
			return false;
		return true;
	}
	if (data->payload_len[1] == 53) {
		if (data->payload_len[0] < 30)
			return false;
		if (data->payload_len[0] > 33)
			return false;
		return true;
	}

	if (data->payload_len[0] == 16)	{
		if (data->payload_len[1] == 18)
			return true;
		if (data->payload_len[1] == 16)
			return true;
		if (data->payload_len[1] == 13)
			return true;
		if (data->payload_len[1] == 0) {
			if (data->server_port == 28960)
				return true;
			if (data->client_port == 28960)
				return true;
		}
	}

	if (data->payload_len[1] == 16)	{
		if (data->payload_len[0] == 18)
			return true;
		if (data->payload_len[0] == 16)
			return true;
		if (data->payload_len[0] == 13)
			return true;
		if (data->payload_len[0] == 0) {
			if (data->server_port == 28960)
				return true;
			if (data->client_port == 28960)
				return true;
		}
	}

	if (data->payload_len[0] >= 16 && data->payload_len[0] <= 19) { 
		if (data->payload_len[1] < 40)
			return false;
		if (data->payload_len[1] > 44)
			return false;
		return true;
	}

	if (data->payload_len[1] >= 16 && data->payload_len[1] <= 19) { 
		if (data->payload_len[0] < 40)
			return false;
		if (data->payload_len[0] > 44)
			return false;
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

static inline bool match_moh(lpi_data_t *data) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff))
		return false;
	if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff))
		return false;
	
	/* This is kinda a broad match, so let's refine it a bit by using the
	 * port number */
	if (data->server_port >= 12200 && data->server_port <= 12210) {

		if (data->payload_len[0] == 16 && data->payload_len[1] > 600)
			return true;
		if (data->payload_len[1] == 16 && data->payload_len[0] > 600)
			return true;
	}

	if (data->client_port >= 12200 && data->client_port <= 12210) {

		if (data->payload_len[0] == 16 && data->payload_len[1] > 600)
			return true;
		if (data->payload_len[1] == 16 && data->payload_len[0] > 600)
			return true;
	}

	return false;
}

static inline bool match_tremulous(lpi_data_t *data) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff)) {
		if (data->payload_len[0] != 0)
			return false;
	}
	if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff)) {
		if (data->payload_len[1] != 0)
			return false;
	}

	/* Not super confident that this won't match other traffic, so
	 * added a port rule here */
	if (data->server_port != 30710 && data->client_port != 30710 &&
			data->client_port != 30711 && 
			data->server_port != 30711) {
		return false;
	}


	if (data->payload_len[0] >= 20 && data->payload_len[0] <= 24) {
		if (data->payload_len[1] == 0)
			return true;
	}
	
	if (data->payload_len[1] >= 20 && data->payload_len[1] <= 24) {
		if (data->payload_len[0] == 0)
			return true;
	}
	
	if (data->payload_len[0] >= 116 && data->payload_len[0] <= 119) {
		if (data->payload_len[1] == 0)
			return true;
	}
	
	if (data->payload_len[1] >= 116 && data->payload_len[1] <= 119) {
		if (data->payload_len[0] == 0)
			return true;
	}

	if (data->payload_len[0] == 37) {
		if (data->payload_len[1] == 98)
			return true;
	}
	if (data->payload_len[1] == 37) {
		if (data->payload_len[0] == 98)
			return true;
	}

	return false;
}

static inline bool match_halflife(lpi_data_t *data) {

	if (!MATCH(data->payload[0], 0xff, 0xff, 0xff, 0xff)) {
		if (data->payload_len[0] != 0)
			return false;
	}
	if (!MATCH(data->payload[1], 0xff, 0xff, 0xff, 0xff)) {
		if (data->payload_len[1] != 0)
			return false;
	}

	if (data->payload_len[0] == 20 || data->payload_len[1] == 20)
		return true;
	if (data->payload_len[1] == 9 || data->payload_len[0] == 9)
		return true;
	if (data->payload_len[0] == 65 && (data->payload_len[1] > 500 &&
			data->payload_len[1] < 600))
		return true;
	if (data->payload_len[1] == 65 && (data->payload_len[0] > 500 &&
			data->payload_len[0] < 600))
		return true;
	if (data->payload_len[0] == 17 && data->payload_len[1] == 27)
		return true;
	if (data->payload_len[1] == 17 && data->payload_len[0] == 27)
		return true;
	

	/* This differs only slightly from Quake-based stuff, which replies
	 * with 51-54 byte packets - hopefully this never overlaps, although
	 * we could combine the two protocols if we have to into a generic
	 * "Quake ancestry" protocol */	
	if (data->payload_len[0] == 16) {
		if (data->payload_len[1] >= 45 && data->payload_len[1] <= 48)
			return true;
	}
	if (data->payload_len[1] == 16) {
		if (data->payload_len[0] >= 45 && data->payload_len[0] <= 48)
			return true;
	}

	/* Another combo observed on port 27005 */
	if (data->payload_len[0] == 87) {
		if (data->payload_len[1] >= 24 && data->payload_len[1] <= 26)
			return true;
	}
	if (data->payload_len[1] == 87) {
		if (data->payload_len[0] >= 24 && data->payload_len[0] <= 26)
			return true;
	}


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

static inline bool match_vuze_dht_reply(uint32_t data, uint32_t len) {

	/* Each reply action is an odd number */
		
	if (MATCH(data, 0x00, 0x00, 0x04, 0x01))
		return true;
	if (MATCH(data, 0x00, 0x00, 0x04, 0x03))
		return true;
	if (MATCH(data, 0x00, 0x00, 0x04, 0x05))
		return true;
	if (MATCH(data, 0x00, 0x00, 0x04, 0x07))
		return true;

	/* Except for this one, which is an error message */
	if (MATCH(data, 0x00, 0x00, 0x04, 0x08))
		return true;

	return false;
	

}

static inline bool match_vuze_dht_request(uint32_t payload, uint32_t len,
		bool check_msb) {


	/* Some implementations don't choose an appropriate MSB or get the
	 * byte ordering wrong, so we only force an MSB check when we're
	 * examining requests that get no response.
	 *
	 * However, we only need to check the payload length in the event
	 * of a unidirectional flow */
	
	if (len < 4)
		return false;
		
	if (check_msb) {



		if ((ntohl(payload) & 0x80000000) != 0x80000000)
			return false;
		if (len == 42) {
			return true;
		}

		if (len == 63 || len == 65 || len == 71)
			return true;

		return false;
	}

	if ((ntohl(payload) & 0x80000000) == 0x80000000)
		return true;
	return false;

}

static inline bool match_vuze_dht(lpi_data_t *data) {

	/* OK, gotta rework this one as this protocol is a bit messed up in 
	 * the implementation.
	 *
	 * Normally, we have a request which contains a random number in
	 * the first four bytes. However, the MSB of that number must be
	 * set to one.
	 *
	 * The reply begins with a four byte action which is easy to identify.
	 *
	 * However, we also get replies in both directions (which is a bit
	 * odd). I'm also seeing requests where the MSB is not set, which is
	 * a definite violation.
	 *
	 * However, I think we want to count these - they are clearly attempts
	 * to use this protocol so classing them as unknown doesn't seem
	 * right.
	 */

	if (match_vuze_dht_reply(data->payload[0], data->payload_len[0])) {

		if (data->payload_len[1] == 0)
			return true;

		if (match_vuze_dht_request(data->payload[1], 
				data->payload_len[1], false))
			return true;

		/* Check for replies in both directions */
		if (match_vuze_dht_reply(data->payload[1],
				data->payload_len[1]))
			return true;

	}

	if (match_vuze_dht_reply(data->payload[1], data->payload_len[1])) {

		if (data->payload_len[0] == 0)
			return true;

		if (match_vuze_dht_request(data->payload[0], 
				data->payload_len[0], false))
			return true;
		
		/* Check for replies in both directions */
		if (match_vuze_dht_reply(data->payload[0],
				data->payload_len[0]))
			return true;

	}

	/* Check for unanswered requests - these are much harder to match,
	 * because they are simply a random conn id. We can only hope to match
	 * on common packet sizes and the MSB being set 
	 *
	 * XXX This could lead to a few false positives, so be careful */

	if (data->payload[0] == 0) {
		if (match_vuze_dht_request(data->payload[1], 
				data->payload_len[1], true))
			return true;
	}

	if (data->payload[1] == 0) {
		if (match_vuze_dht_request(data->payload[0], 
				data->payload_len[0], true))
			return true;
	}

	return false;	
	


}

static inline bool match_unknown_dht(lpi_data_t *data) {

	/* I don't know exactly what BT clients do this, but there are often
	 * DHT queries and responses present in flows that match this rule,
	 * so we're going to go with some form of Bittorrent */

	if (data->payload[0] == 0 || data->payload[1] == 0)
		return false;
	
	/* Both initial packets are 33 bytes and have the exact same 
	 * payload */
	if (data->payload_len[0] != 33 || data->payload_len[1] != 33)
		return false;

	if (data->payload[0] != data->payload[1])
		return false;

	return true;

}

static inline bool match_vivox(lpi_data_t *data) {

	/* Seen this to Vivox servers, so I'm going to make the logical
	 * assumption */
	if (!match_str_both(data, "\x80\x6f\x00\x00", "\x80\x6f\x00\x01"))
		return false;
	
	if (data->payload_len[0] == 108 || data->payload_len[1] == 108)
		return true;

	return false;

}

static inline bool match_ventrilo(lpi_data_t *data) {

	/* We see this on port 6100, so I'm assuming it is the UDP
	 * Ventrilo protocol. No real documentation of it to confirm,
	 * though */

	if (!(match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00")))
		return false;
	
	if (data->payload_len[0] == 108 && data->payload_len[1] == 132)
		return true;
	if (data->payload_len[1] == 108 && data->payload_len[0] == 132)
		return true;
	if (data->payload_len[0] == 52 && data->payload_len[1] == 196)
		return true;
	if (data->payload_len[1] == 52 && data->payload_len[0] == 196)
		return true;

	return false;

}


static inline bool match_xfire_p2p(lpi_data_t *data) {

	if (match_str_both(data, "SC01", "CK01"))
		return true;
	return false;

}

static inline bool match_pyzor(lpi_data_t *data) {
	if (match_str_both(data, "User", "Code"))
		return true;
	if (match_str_both(data, "User", "Thre"))
		return true;
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (match_str_either(data, "User"))
			return true;
	}

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

static inline bool match_xlsp_payload(uint32_t payload, uint32_t len,
		uint32_t other_len) {

	/* This is almost all based on observing traffic on port 3074. Not
	 * very scientific, but seems more or less right */

	
	/* We've only ever seen a few of the packet sizes in one-way flows,
	 * so let's not match any of the others if there is no response */
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00)) {
		if (len == 122)
			return true;
		if (len == 156)
			return true;
		if (len == 82)
			return true;
		if (len == 83 && other_len != 0)
			return true;
		if (len == 43 && other_len != 0)
			return true;
		if (len == 75 && other_len != 0)
			return true;
		if (len == 120 && other_len != 0)
			return true;
		if (len == 0 && other_len != 0)
			return true;
	}

	if (len == 24) {
		if (MATCH(payload, 0x0d, ANY, ANY, ANY))
			return true;
		if (MATCH(payload, 0x80, ANY, ANY, ANY))
			return true;

	}

	if (len == 29) {
		if (MATCH(payload, 0x0c, 0x02, 0x00, ANY))
			return true;
		if (MATCH(payload, 0x0b, 0x02, 0x00, ANY))
			return true;
		if (MATCH(payload, 0x0e, 0x02, 0x00, ANY))
			return true;
	}


	return false;

}

/* XXX Not 100% sure on this because there is little documentation, but I
 * think this is pretty close */
static inline bool match_xlsp(lpi_data_t *data) {


	/* Commonly observed request/response pattern */
	if (match_chars_either(data, 0x0d, 0x02, 0x00, ANY)) {
		if (data->payload_len[0] == 0 && data->payload_len[1] == 29)
			return true;
		if (data->payload_len[1] == 0 && data->payload_len[0] == 29)
			return true;
		if (data->payload_len[0] != 29 || data->payload_len[1] != 29)
			return false;
		if (match_chars_either(data, 0x0c, 0x02, 0x00, ANY))
			return true;
		if (MATCH(data->payload[0], 0x0d, 0x02, 0x00, ANY) && 
				MATCH(data->payload[1], 0x0d, 0x02, 0x00, ANY))
			return true;
		return false;
	}

	/* Unlike other combos, 1336 and 287 (or rarely 286) only go with
	 * each other 
	 *
	 * 1011 (or rarely 1010) is also a possible response */
	if (match_str_both(data, "\x00\x00\x00\x00", "\x00\x00\x00\x00")) {
		if (data->payload_len[0] == 1336) {
			if (data->payload_len[1] == 287)
				return true;
			if (data->payload_len[1] == 1011)
				return true;
			if (data->payload_len[1] == 286)
				return true;
			if (data->payload_len[1] == 1010)
				return true;
			if (data->payload_len[1] == 1003)
				return true;
		}
		if (data->payload_len[1] == 1336) {
			if (data->payload_len[0] == 287)
				return true;
			if (data->payload_len[0] == 1011)
				return true;
			if (data->payload_len[0] == 286)
				return true;
			if (data->payload_len[0] == 1010)
				return true;
			if (data->payload_len[0] == 1003)
				return true;
		}
		
		/* This is something to do with PunkBuster? */
		if (data->payload_len[0] == 4) {
			if (data->payload_len[1] == 4)
				return true;
		}
		if (data->payload_len[1] == 4) {
			if (data->payload_len[0] == 4)
				return true;
		}
	}


	/* Enforce port 3074 being involved, to reduce false positive rate for
	 * one-way transactions */

	if (match_chars_either(data, 0xff, 0xff, 0xff, 0xff)) {
		if (data->server_port != 3074 && data->client_port != 3074)
			return false;
		if (data->payload_len[0] == 14 && data->payload_len[1] == 0)
			return true;
		if (data->payload_len[1] == 14 && data->payload_len[0] == 0)
			return true;
	}

	/* We could also enforce the port number here too, but we still see a 
	 * lot of one-way traffic that matches these rules on other ports.
	 * I'm pretty confident it is XLSP, but this should be watched
	 * closely to make sure it isn't overmatching */
	
	if (!match_xlsp_payload(data->payload[0], data->payload_len[0],
			data->payload_len[1]))
		return false;
	if (!match_xlsp_payload(data->payload[1], data->payload_len[1],
			data->payload_len[0]))
		return false;
	
	return true;

}

static inline bool match_ssdp(lpi_data_t *data) {

	if (match_str_either(data, "M-SE"))
		return true;
	return false;

}

static inline bool match_xunlei(lpi_data_t *data) {


	/* Require port 3076 for now, as all these rules are based on
	 * traffic seen on port 3076 */
	if (data->server_port != 3076 && data->client_port != 3076)
		return false;
	
	if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x35\x00\x00\x00", "\x35\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x35\x00\x00\x00", "\x28\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x35\x00\x00\x00", "\x29\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x34\x00\x00\x00", "\x34\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x34\x00\x00\x00", "\x29\x00\x00\x00"))
		return true;
	if (match_str_both(data, "\x33\x00\x00\x00", "\x33\x00\x00\x00"))
		return true;

	if (match_str_either(data, "\x36\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	if (match_str_either(data, "\x35\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	if (match_str_either(data, "\x34\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	if (match_str_either(data, "\x33\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
	if (match_str_either(data, "\x29\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

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

static inline bool match_ntp_request(uint32_t payload, uint32_t len) {

	uint8_t first;
	uint8_t version;
	uint8_t mode;

	if (len != 48 && len != 68)
		return false;

	first = (uint8_t) (payload);

	version = (first & 0x38) >> 3;
	mode = (first & 0x07);

	if (version > 4 || version == 0)
		return false;
	if (mode != 1 && mode != 3)
		return false;

	return true;

}

static inline bool match_ntp_response(uint32_t payload, uint32_t len) {

	uint8_t first;
	uint8_t version;
	uint8_t mode;

	/* Server may not have replied */
	if (len == 0)
		return true;

	first = (uint8_t) (payload);

	version = (first & 0x38) >> 3;
	mode = (first & 0x07);

	if (version > 4 || version == 0)
		return false;
	if (mode != 4 && mode != 2 && mode != 1)
		return false;
	
	return true;
}

static inline bool match_ntp(lpi_data_t *data) {

	/* Force NTP to be on port 123 */

	if (data->server_port != 123 && data->client_port != 123)
		return false;

	if (match_ntp_request(data->payload[0], data->payload_len[0])) {
		if (match_ntp_response(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_ntp_request(data->payload[1], data->payload_len[1])) {
		if (match_ntp_response(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static inline bool match_snmp_payload(uint32_t payload, uint32_t len) {
	
	/* SNMP is BER encoded, which is an ass to decode */
	uint8_t snmplen = 0;
	uint8_t *byte;
	int i;

	/* Must be a SEQUENCE */
	if (!MATCH(payload, 0x30, ANY, ANY, ANY))
		return false;

	byte = ((uint8_t *)&payload) + 1;
	
	if (*byte< 0x80) {
		snmplen = *byte;

		if (!MATCH(payload, 0x30, ANY, 0x02, 0x01))
			return false;
		if (len - 2 != snmplen)
			return false;
		return true;
	} 
	
	if (*byte == 0x81) {
		snmplen = *(byte + 1);
		
		if (!MATCH(payload, 0x30, 0x81, ANY, 0x02))
			return false;
		if (len - 3 != snmplen)
			return false;
		return true;
	}

	if (*byte == 0x82) {
		uint16_t longlen = *((uint16_t *)(byte + 1));
		
		if (len - 4 != ntohs(longlen))
			return false;
		return true;
	}

	return false;

}

static inline bool match_snmp(lpi_data_t *data) {
	
	if (!match_snmp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_snmp_payload(data->payload[1], data->payload_len[1]))	
		return false;

	return true;
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

	if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
		return false;
	
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
	if (match_chars_either(data, 0x02, 0x01, 0x41, 0x31))
		return true;


	return false;

}

static inline bool match_skype_rule1(lpi_data_t *data) {

	/* This is one method for matching skype traffic - turns out there
	 * are other forms as well... */

	/* The third byte is always 0x02 in Skype UDP traffic - if we have
	 * payload in both directions we can probably match on that alone */

	if (data->payload_len[0] > 0 && data->payload_len[1] > 0) {
		if ((data->payload[0] & 0x00ff0000) != 0x00020000)
			return false;
		if ((data->payload[1] & 0x00ff0000) != 0x00020000)
			return false;
		return true;
	}

	/* Probes with no responses are trickier - likelihood of a random
	 * packet having 0x02 as the third byte is not small, so we'll try
	 * and filter on packet size too */

	if (data->payload_len[0] >= 28 && data->payload_len[0] <= 130 ) {
		if ((data->payload[0] & 0x00ff0000) == 0x00020000)
			return true;
	}
	if (data->payload_len[1] >= 28 && data->payload_len[1] <= 130 ) {
		if ((data->payload[1] & 0x00ff0000) == 0x00020000)
			return true;
	}

	return false;
}

static inline bool match_skype_U1(uint32_t payload, uint32_t len) {

	if (len < 18 || len > 27)
		return false;
	if ((payload & 0x00ff0000) == 0x00020000)
		return true;

	return false;

}

static inline bool match_skype_U2(uint32_t payload, uint32_t len) {

	if (len != 11)
		return false;
	if ((payload & 0x000f0000) == 0x00050000)
		return true;
	if ((payload & 0x000f0000) == 0x00070000)
		return true;
	return false;
}

static inline bool match_skype_rule2(lpi_data_t *data) {

	/* What we're looking for here is a initiating message (called U1)
	 * matched with a response (called U2).
	 *
	 * The first two bytes of U1 and U2 must match.
	 *
	 * The third byte of U1 is always 0x02 (as with rule 1)
	 * 
	 * The lower four bits of the third byte of U2 is always either 0x05
	 * or 0x07
	 *
	 * The length of U2 is always 11 bytes.
	 *
	 * The length of U1 is always between 18 and 27 bytes.
	 */

	if ((data->payload[0] & 0x0000ffff) != (data->payload[1] & 0x0000ffff))
		return false;

	if (match_skype_U1(data->payload[0], data->payload_len[0])) {
		if (match_skype_U2(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_skype_U1(data->payload[1], data->payload_len[1])) {
		if (match_skype_U2(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static inline bool match_skype(lpi_data_t *data) {
	if (match_skype_rule1(data))
		return true;
	if (match_skype_rule2(data))
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

static inline bool match_newerth_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	if (MATCH(payload, 0x00, 0x00, 0x01, 0x66))
		return true;
	if (MATCH(payload, 0x00, 0x00, 0x01, 0xca) && len == 6)
		return true;
	return false;
}

static inline bool match_heroes_newerth(lpi_data_t *data) {

	if (!match_newerth_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_newerth_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;

}

static inline bool match_thq(lpi_data_t *data) {

	/* I *suspect* this is the protocol used by RTS games released by
	 * THQ - haven't been able to confirm for sure, though
	 *
	 * Most traffic is on port 6112, which is used by Blizzard and THQ
	 * games, but we already have rules for most Blizzard stuff */

	/* The ANY byte also matches the packet length - 17, if we need 
	 * further matching rules */
	if (data->payload_len[0] != 0 &&
			!MATCH(data->payload[0], 'Q', 'N', 'A', ANY))
		return false;
	if (data->payload_len[1] != 0 &&
			!MATCH(data->payload[1], 'Q', 'N', 'A', ANY))
		return false;

	return true;
}

static inline bool match_diablo2_message(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (MATCH(payload, 0x03, 0x00, 0x00, 0x00) && len == 8)
		return true;
	if (MATCH(payload, 0x05, 0x00, 0x00, 0x00) && len == 8)
		return true;
	if (MATCH(payload, 0x09, 0x00, 0x00, 0x00) && len == 12)
		return true;

	return false;
}

static inline bool match_diablo2(lpi_data_t *data) {

	if (data->server_port != 6112 && data->client_port != 6112)
		return false;
	
	if (!match_diablo2_message(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_diablo2_message(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static inline bool match_unreal_query(uint32_t payload, uint32_t len) {

	/* UT2004 retail is 0x80, demo is 0x7f */

	/* Queries are 5 bytes */
	if (len != 5)
		return false;
	if (MATCH(payload, 0x80, 0x00, 0x00, 0x00)) 
		return true;
	if (MATCH(payload, 0x7f, 0x00, 0x00, 0x00)) 
		return true;
	return false;

}

static inline bool match_unreal(lpi_data_t *data) {

	/* http://www.unrealadmin.org/forums/showthread.php?p=56944 */

	if (match_unreal_query(data->payload[0], data->payload_len[0])) {
		if (MATCH(data->payload[1], 0x80, 0x00, 0x00, 0x00))
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	if (match_unreal_query(data->payload[1], data->payload_len[1])) {
		if (MATCH(data->payload[0], 0x80, 0x00, 0x00, 0x00))
			return true;
		if (data->payload_len[0] == 0)
			return true;
	}

	return false;
}

static inline bool match_sc_message(uint32_t payload, uint32_t len) {

	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00) && len == 16)
		return true;
	if (MATCH(payload, 0x00, 0x00, 0x00, 0x00) && len == 17)
		return true;

	return false;
}

static inline bool match_starcraft(lpi_data_t *data) {

	if (data->server_port != 6112 && data->client_port != 6112)
		return false;

	if (!match_sc_message(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_sc_message(data->payload[1], data->payload_len[1]))
		return false;

	return true;

}

static inline bool match_tftp(lpi_data_t *data) {


	/* Read request */	
	if (MATCH(data->payload[0], 0x00, 0x01, ANY, ANY)) {
		if (data->server_port != 69 && data->client_port != 69)
			return false;
		if (data->payload_len[1] == 0)
			return true;
		if (MATCH(data->payload[1], 0x00, 0x03, ANY, ANY))
			return true;
		if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
			return true;
	}

	if (MATCH(data->payload[1], 0x00, 0x01, ANY, ANY)) {
		if (data->server_port != 69 && data->client_port != 69)
			return false;
		if (data->payload_len[0] == 0)
			return true;
		if (MATCH(data->payload[0], 0x00, 0x03, ANY, ANY))
			return true;
		if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
			return true;
	}

	/* Write request */
	if (MATCH(data->payload[0], 0x00, 0x02, ANY, ANY)) {
		if (data->server_port != 69 && data->client_port != 69)
			return false;
		if (data->payload_len[1] == 0)
			return true;
		if (MATCH(data->payload[1], 0x00, 0x04, ANY, ANY))
			return true;
		if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
			return true;
	}

	if (MATCH(data->payload[1], 0x00, 0x02, ANY, ANY)) {
		if (data->server_port != 69 && data->client_port != 69)
			return false;
		if (data->payload_len[0] == 0)
			return true;
		if (MATCH(data->payload[0], 0x00, 0x04, ANY, ANY))
			return true;
		if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
			return true;
	}

	/* Some systems will switch to a different port for the file 
	 * transfer itself, so the request is in a different flow */
	if (MATCH(data->payload[0], 0x00, 0x03, 0x00, 0x01)) {
		if (data->payload_len[1] == 0)
			return true;
		if (MATCH(data->payload[1], 0x00, 0x05, ANY, ANY))
			return true;
		
		/* Acks (0x04) must be 4 bytes */
		if (data->payload_len[1] != 4)
			return false;
		if (MATCH(data->payload[1], 0x00, 0x04, 0x00, 0x01))
			return true;
	}

	if (MATCH(data->payload[1], 0x00, 0x03, 0x00, 0x01)) {
		if (data->payload_len[0] == 0)
			return true;
		if (MATCH(data->payload[0], 0x00, 0x05, ANY, ANY))
			return true;
		
		/* Acks (0x04) must be 4 bytes */
		if (data->payload_len[0] != 4)
			return false;
		if (MATCH(data->payload[0], 0x00, 0x04, 0x00, 0x01))
			return true;
	}

	return false;

}

static inline bool match_rtcp_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	if (MATCH(payload, 0x81, 0xc8, 0x00, 0x0c))
		return true;
	if (MATCH(payload, 0x80, 0xc9, 0x00, 0x01))
		return true;
	return false;
}

static inline bool match_rtcp(lpi_data_t *data) {

	if (!match_rtcp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_rtcp_payload(data->payload[1], data->payload_len[1]))
		return false;
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

static inline bool match_linkproof(lpi_data_t *data) {

	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;

	if (!match_str_either(data, "link"))
		return false;

	if (data->payload_len[0] == 50 || data->payload_len[1] == 50)
		return true;
	
	return false;
}

static inline bool match_backweb(lpi_data_t *data) {

	if (data->server_port != 370 && data->client_port != 370)
		return false;

	if (match_chars_either(data, 0x21, 0x24, 0x00, ANY))
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

	/* This is something I've observed going to hosts belonging to
	 * Pando */

	if (match_str_both(data, "UDPA", "UDPR"))
		return true;
	if (match_str_both(data, "UDPA", "UDPE"))
		return true;

	return false;
}

static inline bool match_mystery_emule(lpi_data_t *data) {

	/* These particular patterns occur frequently on port 4672, making
	 * me think they're some sort of emule traffic but there is no
	 * obvious documentation. The payloads appear to be random, which
	 * is unlike all other emule traffic. The flows tend to consist of
	 * only one or two packets in each direction.
	 */

	if (data->payload_len[0] == 44 && data->payload_len[1] >= 38 &&
			data->payload_len[1] <= 50)
		return true;
	if (data->payload_len[1] == 44 && data->payload_len[0] >= 38 &&
			data->payload_len[0] <= 50)
		return true;
	
	if (data->payload_len[0] == 51 && (data->payload_len[1] == 135 ||
			data->payload_len[1] == 85 || 
			data->payload_len[1] == 310))
		return true;
	if (data->payload_len[1] == 51 && (data->payload_len[0] == 135 ||
			data->payload_len[0] == 85 || 
			data->payload_len[0] == 310))
		return true;

	return false;

}

static inline bool match_kad(uint32_t payload, uint32_t len) {

	/* Many of these can be tracked back to
	 * http://easymule.googlecode.com/svn/trunk/src/WorkLayer/opcodes.h
	 *
	 * XXX Some of these are request/response pairs that we may need to
	 * match together if we start getting false positives 
	 */

	
	/* Bootstrap version 2 request and response */
	if (MATCH(payload, 0xe4, 0x00, ANY, ANY) && len == 27) 
		return true;
	if (MATCH(payload, 0xe4, 0x08, ANY, ANY) && len == 529)
		return true;

	/* Bootstrap version 2 request and response */
	if (MATCH(payload, 0xe4, 0x01, 0x00, 0x00) && (
			len == 2 || len == 18)) 
		return true;
	if (MATCH(payload, 0xe4, 0x09, ANY, ANY) && len == 523)
		return true;


	if (MATCH(payload, 0xe4, 0x21, ANY, ANY) && len == 35) 
		return true;
	if (MATCH(payload, 0xe4, 0x4b, ANY, ANY) && len == 19) 
		return true;
	if (MATCH(payload, 0xe4, 0x11, ANY, ANY)) {
		if (len == 22 || len == 38 || len == 28 || len == 36 ||
				len == 34) 
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

	if (MATCH(payload, 0xe4, 0x52, ANY, ANY) && len == 36)
		return true;
	
	if (MATCH(payload, 0xe4, 0x40, ANY, ANY) && len == 48)
		return true;
	
	if (MATCH(payload, 0xe4, 0x43, ANY, ANY) && len == 225)
		return true;
	
	if (MATCH(payload, 0xe4, 0x48, ANY, ANY) && len == 19)
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
	if (MATCH(payload, 0xe5, 0x08, 0x78, 0xda))
		return true;

	/* emule extensions */
	if (MATCH(payload, 0xc5, 0x90, ANY, ANY)) {
		return true;
	}
	if (MATCH(payload, 0xc5, 0x91, ANY, ANY)) {
		return true;
	}
	if (MATCH(payload, 0xc5, 0x92, ANY, ANY) && (len == 2))
		return true;
	if (MATCH(payload, 0xc5, 0x93, ANY, ANY) && (len == 2))
		return true;
	if (MATCH(payload, 0xc5, 0x94, ANY, ANY)) {
		if (len >= 38 && len <= 70)
			return true;
	}

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
	if (MATCH(payload, 0xe3, 0x94, ANY, ANY))
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

static inline bool match_cisco_ipsec_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len == 109)
		return true;
	if (len == 93)
		return true;
	return false;

}

static inline bool match_cisco_ipsec(lpi_data_t *data) {

	/* Been seeing this on UDP port 10000, which I assume is the
	 * Cisco IPSec VPN */

	if (data->server_port != 10000 && data->client_port != 10000)
		return false;

	if (!match_cisco_ipsec_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_cisco_ipsec_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;

}

static inline bool match_mys_fe_payload(uint32_t payload, uint32_t len) {

	uint16_t length;
	uint8_t *ptr;

	/* This appears to have a 3 byte header. First byte is always 0xfe.
	 * Second and third bytes are the length (minus the 3 byte header).
	 */

	if (!MATCH(payload, 0xfe, ANY, ANY, ANY))
		return false;

	ptr = ((uint8_t *)&payload) + 1;
	length = (*((uint16_t *)ptr));

	if (length = len - 3)
		return true;
	
	return false;

}

static inline bool match_mystery_fe(lpi_data_t *data) {

	/* Again, not entirely sure what protocol this is, but we've come up
	 * with a good rule for it. 
	 *
	 * Every packet begins with a 3 byte header - 0xfe followed by a
	 * length field
	 */

	if (!match_mys_fe_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_mys_fe_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static inline bool match_mystery_02_36(lpi_data_t *data) {

	/* Another mystery protocol :/
	 *
	 * Characterised by 36 byte datagrams in both directions, always
	 * beginning with 02 00 XX 00.
	 *
	 * Later packets also begin with 02 and have 00 in the fourth byte.
	 * Packet size varies.
	 */
	
	if (MATCH(data->payload[0], 0x02, 0x00, ANY, ANY) &&
			data->payload_len[0] == 36) {
		if (data->payload_len[1] == 0)
			return true;
		if (MATCH(data->payload[1], 0x02, 0x00, ANY, ANY) && 
				data->payload_len[1] == 36)
			return true;
	}

	if (MATCH(data->payload[1], 0x02, 0x00, ANY, ANY) &&
			data->payload_len[1] == 36) {
		if (data->payload_len[0] == 0)
			return true;
		if (MATCH(data->payload[0], 0x02, 0x00, ANY, ANY) && 
				data->payload_len[0] == 36)
			return true;
	}

	return false;

}

static inline bool match_mystery_0d(lpi_data_t *data) {

	/* This protocol has driven me nuts for weeks. It's pretty easy to
	 * match - one direction sends a single byte datagram containing 0x0d,
	 * the other responds with a 25 byte packet beginning with 0x0a. The
	 * next three bytes of the response appear to be some sort of flow id
	 * that is repeated in all subsequent packets > 1 byte.
	 *
	 * Other codes used during the exchange are 0x0b, 0x15 and 0x1e.
	 *
	 * However, there appears to be no info on the Internet about what this
	 * protocol is. Random ports are always used for both ends, so no help
	 * there.
	 *
	 * TODO Figure out what the hell this is and give it a better name
	 * than "mystery_0d" !
	 */

	if (data->payload_len[0]==1 && MATCH(data->payload[0], 0x0d, 0, 0, 0)) {
		if (data->payload_len[1] == 25 && 
				MATCH(data->payload[1], 0x0a, ANY, ANY, ANY))
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	if (data->payload_len[1]==1 && MATCH(data->payload[1], 0x0d, 0, 0, 0)) {
		if (data->payload_len[0] == 25 && 
				MATCH(data->payload[0], 0x0a, ANY, ANY, ANY))
			return true;
		if (data->payload_len[0] == 0)
			return true;
	}
	
	return false;


}

static inline bool match_mystery_99(lpi_data_t *data) {

	/* Another mystery protocol - this one is possibly something to do
	 * with bittorrent, as I've seen it on port 6881 from time to time */

	/* Both payloads must match */
	if (data->payload[0] != data->payload[1])
		return false;
	
	/* One of the payloads is 99 bytes, the other is between 168 and 173
	 * bytes */

	if (data->payload_len[0] == 99) {
		if (data->payload_len[1] >= 168 && data->payload_len[1] <= 173)
			return true;
	}

	if (data->payload_len[1] == 99) {
		if (data->payload_len[0] >= 168 && data->payload_len[0] <= 173)
			return true;
	}

	return false;
}

static inline bool match_8000_payload(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	if (MATCH(payload, 0x3b, 0x00, 0x00, 0x00)) {
		return true;	
	}
	if (MATCH(payload, 0x3c, 0x00, 0x00, 0x00)) {
		return true;	
	}
	if (MATCH(payload, 0x3d, 0x00, 0x00, 0x00)) {
		return true;	
	}
	if (MATCH(payload, 0x3e, 0x00, 0x00, 0x00)) {
		return true;	
	}

	return false;
}

inline bool match_mystery_8000(lpi_data_t *data) {

	/* These patterns typically appear on UDP port 8000 (and occasionally
	 * TCP port 80) */

	if (!match_8000_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_8000_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

lpi_protocol_t guess_udp_protocol(lpi_data_t *proto_d) {

	if (proto_d->payload_len[0] == 0 && proto_d->payload_len[1] == 0)
		return LPI_PROTO_NO_PAYLOAD;


        if (match_sip(proto_d))
                return LPI_PROTO_UDP_SIP;

	/* XXX May want to separate Vuze DHT from the other DHT at some point */
        if (match_chars_either(proto_d, 'd', '1', ':', ANY))
                return LPI_PROTO_UDP_BTDHT;
        if (match_chars_either(proto_d, 'd', '1', ANY, ':'))
                return LPI_PROTO_UDP_BTDHT;

	if (match_gamespy(proto_d)) return LPI_PROTO_UDP_GAMESPY;

        if (match_chars_either(proto_d, 0x01, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

        if (match_chars_either(proto_d, 0x02, 0x01, 0x06, 0x00))
                return LPI_PROTO_UDP_DHCP;

	if (match_traceroute(proto_d)) return LPI_PROTO_UDP_TRACEROUTE;

        if (match_steam(proto_d)) return LPI_PROTO_UDP_STEAM;

	if (match_stun(proto_d)) return LPI_PROTO_UDP_STUN;

        if (match_chars_either(proto_d, 'G', 'N', 'D', ANY))
                return LPI_PROTO_UDP_GNUTELLA2;
	if (match_gnutella_oob(proto_d))
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
	if (match_pyzor(proto_d)) return LPI_PROTO_UDP_PYZOR;


        if (match_str_either(proto_d, "EYE1"))
                return LPI_PROTO_UDP_EYE;

	if (match_messenger_spam(proto_d))
		return LPI_PROTO_UDP_WIN_MESSAGE;

	if (match_rtp(proto_d))
                return LPI_PROTO_UDP_RTP;

	if (match_chars_either(proto_d, 0x40, 0x00, 0x00, 0x00))
		return LPI_PROTO_UDP_SECONDLIFE;

	if (match_sql_worm(proto_d)) return LPI_PROTO_UDP_SQLEXP;

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

	if (match_rdt(proto_d)) return LPI_PROTO_UDP_REAL;

	if (match_isakmp(proto_d)) return LPI_PROTO_UDP_ISAKMP;

	if (match_snmp(proto_d)) return LPI_PROTO_UDP_SNMP;

	if (match_backweb(proto_d)) return LPI_PROTO_UDP_BACKWEB;

	if (match_thq(proto_d)) return LPI_PROTO_UDP_THQ;

	if (match_linkproof(proto_d)) return LPI_PROTO_UDP_LINKPROOF;

	if (match_xfire_p2p(proto_d)) return LPI_PROTO_UDP_XFIRE_P2P;

	if (match_ssdp(proto_d)) return LPI_PROTO_UDP_SSDP;

	if (match_heroes_newerth(proto_d)) return LPI_PROTO_UDP_NEWERTH;

	if (match_str_either(proto_d, " VRV")) return LPI_PROTO_UDP_WORM_22105;

	/* Not sure what exactly this is, but I'm pretty sure it is related to
	 * BitTorrent - XXX name these functions better! */
	if (match_other_btudp(proto_d)) return LPI_PROTO_UDP_BTDHT;
       
       	if (match_starcraft(proto_d)) return LPI_PROTO_UDP_STARCRAFT;

	if (match_qq(proto_d)) return LPI_PROTO_UDP_QQ;

	if (match_slp(proto_d)) return LPI_PROTO_UDP_SLP;

	if (match_eso(proto_d)) return LPI_PROTO_UDP_ESO;

	if (match_netbios(proto_d)) return LPI_PROTO_UDP_NETBIOS;

	if (match_gta4(proto_d)) return LPI_PROTO_UDP_GTA4;

	if (match_pplive(proto_d)) return LPI_PROTO_UDP_PPLIVE;

	if (match_checkpoint_rdp(proto_d)) return LPI_PROTO_UDP_CP_RDP;        

	if (match_ventrilo(proto_d)) return LPI_PROTO_UDP_VENTRILO;

	if (match_vivox(proto_d)) return LPI_PROTO_UDP_VIVOX;

	if (match_teamspeak(proto_d)) return LPI_PROTO_UDP_TEAMSPEAK;

	if (match_directconnect(proto_d)) return LPI_PROTO_UDP_DC;

	if (match_ipmsg(proto_d)) return LPI_PROTO_UDP_IPMSG;
	
	/* Multitheftauto uses ASE on UDP to ping servers */
	if (match_ase_ping(proto_d)) return LPI_PROTO_UDP_MTA;
	
	if (match_jedi_academy(proto_d)) return LPI_PROTO_UDP_JEDI;

	if (match_xlsp(proto_d)) return LPI_PROTO_UDP_XLSP;
       
	/* Make sure this comes after XLSP */
	if (match_cod(proto_d)) return LPI_PROTO_UDP_COD;

	if (match_quake(proto_d)) return LPI_PROTO_UDP_QUAKE;

	if (match_moh(proto_d)) return LPI_PROTO_UDP_MOH;
	
	if (match_tremulous(proto_d)) return LPI_PROTO_UDP_TREMULOUS;

	if (match_freechal(proto_d)) return LPI_PROTO_UDP_FREECHAL;
	
	if (match_kazaa(proto_d)) return LPI_PROTO_UDP_KAZAA;

	if (match_xunlei(proto_d)) return LPI_PROTO_UDP_XUNLEI;

	if (match_norton(proto_d)) return LPI_PROTO_UDP_NORTON;

	if (match_cisco_ipsec(proto_d)) return LPI_PROTO_UDP_CISCO_VPN;

	if (match_rtcp(proto_d)) return LPI_PROTO_UDP_RTCP;

	if (match_unreal(proto_d)) return LPI_PROTO_UDP_UNREAL;

	if (match_tftp(proto_d)) return LPI_PROTO_UDP_TFTP;

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
	
	if (match_vuze_dht(proto_d)) return LPI_PROTO_UDP_BTDHT;
	if (match_xbt_tracker(proto_d)) return LPI_PROTO_UDP_BTDHT;
	if (match_unknown_dht(proto_d)) return LPI_PROTO_UDP_BTDHT;

	/* This is a bit dodgy too, so keep it near the end */
	if (match_skype(proto_d))
		return LPI_PROTO_UDP_SKYPE;

	/* This matches only on payload size in some instances, so needs to be
	 * near the end */	
	if (match_gnutella(proto_d))
		return LPI_PROTO_UDP_GNUTELLA;
	if (match_esp_encap(proto_d)) return LPI_PROTO_UDP_ESP;

	if (match_mystery_emule(proto_d))
		return LPI_PROTO_UDP_EMULE_MYSTERY;

	if (match_mystery_0d(proto_d))
		return LPI_PROTO_UDP_MYSTERY_0D;
	if (match_mystery_02_36(proto_d))
		return LPI_PROTO_UDP_MYSTERY_02_36;
	if (match_mystery_fe(proto_d))
		return LPI_PROTO_UDP_MYSTERY_FE;
	if (match_mystery_99(proto_d))
		return LPI_PROTO_UDP_MYSTERY_99;
	if (match_mystery_8000(proto_d))
		return LPI_PROTO_UDP_MYSTERY_8000;


        return LPI_PROTO_UDP;
}


