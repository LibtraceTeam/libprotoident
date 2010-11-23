
#include "libprotoident.h"
#include "proto_common.h"
#include "proto_tcp.h"

static inline bool match_smtp_banner(uint32_t payload, uint32_t len) {

	/* Stupid servers that only send the banner one or two bytes at
	 * a time! */

	if (len == 1) {
		if (MATCH(payload, '2', 0x00, 0x00, 0x00))
			return true;
		return false;
	}
	if (len == 2) {
		if (MATCH(payload, '2', '2', 0x00, 0x00))
			return true;
		return false;
	}
	if (len == 3) {
		if (MATCH(payload, '2', '2', '0', 0x00))
			return true;
		return false;
	}
	
	if (MATCH(payload, '2', '2', '0', ' '))
		return true;

	if (MATCH(payload, '2', '2', '0', '-'))
		return true;

	return false;
}

static inline bool match_smtp_command(uint32_t payload, uint32_t len) {

	if (MATCHSTR(payload, "EHLO"))
		return true;
	if (MATCHSTR(payload, "ehlo"))
		return true;
	if (MATCHSTR(payload, "HELO"))
		return true;
	if (MATCHSTR(payload, "helo"))
		return true;
	if (MATCHSTR(payload, "NOOP"))
		return true;
	if (MATCHSTR(payload, "XXXX"))
		return true;

	/* Turns out there are idiots who send their ehlos one byte at a 
	 * time :/ */
	if (MATCH(payload, 'e', 0x00, 0x00, 0x00) && len == 1)
		return true;
	if (MATCH(payload, 'E', 0x00, 0x00, 0x00) && len == 1)
		return true;
	if (MATCH(payload, 'h', 0x00, 0x00, 0x00) && len == 1)
		return true;
	if (MATCH(payload, 'H', 0x00, 0x00, 0x00) && len == 1)
		return true;

	return false;

}

static inline bool match_smtp(lpi_data_t *data) {


	/* Match all the random error codes */	
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {
		if (match_str_either(data, "220 "))
			return true;
		if (match_str_either(data, "450 "))
			return true;
		if (match_str_either(data, "421 "))
			return true;
		if (match_str_either(data, "451 "))
			return true;
		if (match_str_either(data, "451-"))
			return true;
		if (match_str_either(data, "452 "))
			return true;
		if (match_str_either(data, "420 "))
			return true;
		if (match_str_either(data, "571 "))
			return true;
		if (match_str_either(data, "553 "))
			return true;
		if (match_str_either(data, "554 "))
			return true;
		if (match_str_either(data, "554-"))
			return true;
		if (match_str_either(data, "476 "))
			return true;
	}

	if (match_str_either(data, "QUIT") && (data->server_port == 25 || 
			data->client_port == 25))
		return true;
	if (match_str_either(data, "quit") && (data->server_port == 25 ||
			data->client_port == 25))
		return true;


	/* Match the server banner code */

	if (match_smtp_banner(data->payload[0], data->payload_len[0])) {
		if (match_smtp_command(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_smtp_banner(data->payload[1], data->payload_len[1])) {
		if (match_smtp_command(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static inline bool match_rbls(lpi_data_t *data) {

	if (match_str_either(data, "rbls"))
		return true;
	return false;
}

static inline bool match_pdbox(lpi_data_t *data) {

	if (match_str_both(data, "0127", "0326"))
		return true;
	return false;
}

static inline bool match_steam(lpi_data_t *data) {

	if (match_str_either(data, "\x00\x00\x00\x07") &&
			match_str_either(data, "\x01\x00\x00\x00") &&
			data->server_port == 27030) {
		return true;
	}
	return false;
}

static inline bool match_rtmp(lpi_data_t *data) {

	if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
		return false;

	if (MATCH(data->payload[0], 0x03, ANY, ANY, ANY) &&
			MATCH(data->payload[1], 0x03, ANY, ANY, ANY)) {

		return true;
	}
	
	return false;

}

static inline bool match_conquer_online(lpi_data_t *data) {

	if (data->payload_len[0] == 5 && data->payload_len[1] == 4 &&
			MATCH(data->payload[0], 'R', 'E', 'A', 'D'))
		return true;
	if (data->payload_len[1] == 5 && data->payload_len[0] == 4 &&
			MATCH(data->payload[1], 'R', 'E', 'A', 'D'))
		return true;
	
	if (data->payload_len[0] == 4 && (MATCH(data->payload[0], '5', '0', ANY, ANY) ||
			MATCH(data->payload[0], '5', '1', ANY, ANY)) &&
			MATCH(data->payload[1], 'U', 'P', 'D', 'A'))
		return true;

	if (data->payload_len[1] == 4 && (MATCH(data->payload[1], '5', '0', ANY, ANY) ||
			MATCH(data->payload[1], '5', '1', ANY, ANY)) &&
			MATCH(data->payload[0], 'U', 'P', 'D', 'A'))
		return true;

	return false;

}

static inline bool match_ftp_data(lpi_data_t *data) {

        /* FTP data tends to be a one-way exchange so we shouldn't see
         * payload in both directions */
        /*
        if (data->server_port == 20 || data->client_port == 20) {
                printf("%u %u\n", data->payload_len[0], data->payload_len[1]);
        }
        */

        if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
                return false;

        /* FTP Data can start with directory permissions */
        if (    (MATCH(data->payload[0], '-', ANY, ANY, ANY) ||
                MATCH(data->payload[0], 'd', ANY, ANY, ANY)) &&
                (MATCH(data->payload[0], ANY, '-', ANY, ANY) ||
                MATCH(data->payload[0], ANY, 'r', ANY, ANY)) &&
                (MATCH(data->payload[0], ANY, ANY, '-', ANY) ||
                MATCH(data->payload[0], ANY, ANY, 'w', ANY)) &&
                (MATCH(data->payload[0], ANY, ANY, ANY, '-') ||
                MATCH(data->payload[0], ANY, ANY, ANY, 'x')) )

                return true;

        if (    (MATCH(data->payload[1], '-', ANY, ANY, ANY) ||
                MATCH(data->payload[1], 'd', ANY, ANY, ANY)) &&
                (MATCH(data->payload[1], ANY, '-', ANY, ANY) ||
                MATCH(data->payload[1], ANY, 'r', ANY, ANY)) &&
                (MATCH(data->payload[1], ANY, ANY, '-', ANY) ||
                MATCH(data->payload[1], ANY, ANY, 'w', ANY)) &&
                (MATCH(data->payload[1], ANY, ANY, ANY, '-') ||
                MATCH(data->payload[1], ANY, ANY, ANY, 'x')) )

                return true;

        /* XXX - I hate having to look at port numbers but there are no
         * useful headers in FTP data exchanges; all the FTP protocol stuff
         * is done using the control channel */
        if (data->client_port == 20 || data->server_port == 20)
                return true;

        return false;
}

static bool match_dns_zone_transfer(lpi_data_t *data) {

	uint16_t length;

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return false;

	if (data->server_port != 53 && data->client_port != 53)
		return false;
	
	length = *((uint16_t *)&data->payload[0]);

	if (ntohs(length) != data->payload_len[0] - 2)
		return false;

	length = *((uint16_t *)&data->payload[1]);

	if (ntohs(length) != data->payload_len[1] - 2)
		return false;

	return true;
}

static bool dns_req(uint32_t payload) {

	/* The flags / rcode on requests are usually all zero.
	 *
	 * Exceptions: CB and RD may be set 
	 *
	 * Remember BYTE ORDER!
	 */

	if ((payload & 0xffff0000) == 0x00000000)
		return true;
	if ((payload & 0xffff0000) == 0x10000000)
		return true;
	if ((payload & 0xffff0000) == 0x00010000)
		return true;

	return false;

}

inline bool match_dns(lpi_data_t *data) {

	if (data->payload_len[0] == 0 || data->payload_len[1] == 0) {

		/* No response, so we have a bit of a hard time - however,
		 * most requests have a pretty standard set of flags.
		 *
		 * We'll also use the port here to help out */
		if (data->server_port != 53 && data->client_port != 53)
			return false;
		if (data->payload_len[0] > 12 && dns_req(data->payload[0]))
			return true;
		if (data->payload_len[1] > 12 && dns_req(data->payload[1]))
			return true;

		return false;
	}

        if ((data->payload[0] & 0x0078ffff) != (data->payload[1] & 0x0078ffff))
                return false;

        if ((data->payload[0] & 0x00800000) == (data->payload[1] & 0x00800000))
                return false;

        return true;
}

static inline bool match_bitextend(lpi_data_t *data) {

        if (match_str_both(data, "\x0\x0\x0\xd", "\x0\x0\x0\x1"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x38"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x39"))
                return true;
        if (match_str_both(data, "\x0\x0\x0\x3", "\x0\x0\x0\x3"))
                return true;

        if (match_str_both(data, "\x0\x0\x0\x4e", "\x0\x0\x0\xb2"))
                return true;
        if (match_chars_either(data, 0x00, 0x00, 0x40, 0x09))
                return true;

        if (MATCH(data->payload[0], 0x00, 0x00, 0x01, ANY) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x38))
                return true;
        if (MATCH(data->payload[1], 0x00, 0x00, 0x01, ANY) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x38))
                return true;

        if (MATCH(data->payload[0], 0x00, 0x00, 0x00, ANY) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x05))
                return true;
        if (MATCH(data->payload[1], 0x00, 0x00, 0x00, ANY) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x05))
                return true;

        if (MATCH(data->payload[0], 0x01, 0x00, ANY, 0x68) &&
                MATCH(data->payload[1], 0x00, 0x00, 0x00, 0x05))
                return true;
        if (MATCH(data->payload[1], 0x01, 0x00, ANY, 0x68) &&
                MATCH(data->payload[0], 0x00, 0x00, 0x00, 0x05))
                return true;

        return false;

}

static inline bool match_imesh_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	
	if (len == 2 && MATCH(payload, 0x06, 0x00, 0x00, 0x00))
		return true;
	if (len == 10 && MATCH(payload, 0x06, 0x00, 0x04, 0x00))
		return true;
	if (len == 12 && MATCH(payload, 0x06, 0x00, 0x06, 0x00))
		return true;
	return false;
	
}

static inline bool match_imesh(lpi_data_t *data) {
	
	/* Credit for this rule goes to opendpi - so if they're wrong then
	 * we're wrong! */

	if (!match_imesh_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_imesh_payload(data->payload[1], data->payload_len[1]))
		return false;
	return true;
}

static inline bool match_message4u(lpi_data_t *data) {
	if (match_str_either(data, "m4ul"))
		return true;
	return false;
}

static inline bool match_wow_request(uint32_t payload, uint32_t len) {

	if (!MATCH(payload, 0x00, 0x08, ANY, 0x00))
		return false;

	payload = ntohl(payload);

	/* 3rd and 4th bytes are the size of the packet, minus the four
	 * byte header */
	if (htons(payload & 0xffff) == len - 4)
		return true;

	return false;
}

static inline bool match_wow_response(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	
	if (len != 119)
		return false;
	
	if (!MATCH(payload, 0x00, 0x00, 0x00, ANY))
		return false;
	
	return true;

}

static inline bool match_wow(lpi_data_t *data) {

	if (match_wow_request(data->payload[0], data->payload_len[0])) {
		if (match_wow_response(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_wow_request(data->payload[1], data->payload_len[1])) {
		if (match_wow_response(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}

static inline bool match_blizzard(lpi_data_t *data) {

        if (match_str_both(data, "\x10\xdf\x22\x00", "\x10\x00\x00\x00"))
                return true;

        if (MATCH(data->payload[0], 0x00, ANY, 0xed, 0x01) &&
                MATCH(data->payload[1], 0x00, 0x06, 0xec, 0x01))
                return true;
        if (MATCH(data->payload[1], 0x00, ANY, 0xed, 0x01) &&
                MATCH(data->payload[0], 0x00, 0x06, 0xec, 0x01))
                return true;

        return false;
}

static inline bool match_http_badport(lpi_data_t *data) {

	/* For some reason, some clients send GET messages to servers on
	 * port 443, which unsurprisingly do not respond. I'm putting this
	 * in a separate category to avoid mixing it in with legitimate
	 * HTTP traffic */

	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;

	if (!match_str_either(data, "GET "))
		return false;

	if (data->server_port == 443 || data->client_port == 443)
		return true;

	return false;

}

static inline bool match_yahoo_error(lpi_data_t *data) {

	/* Yahoo seems to respond to HTTP errors in a really odd way - it
	 * opens up a new connection and just sends raw HTML with the
	 * error message in it. Not sure how they expect that to work, though.
	 */

	if (data->payload_len[0] != 0 && data->payload_len[1] != 0)
		return false;
	
	/* The html isn't entirely valid either - they start with <HEAD>
	 * rather than <HTML>...
	 */
	if (match_str_either(data, "<HEA"))
		return true;
	return false;

}

static inline bool match_telecomkey(lpi_data_t *data) {

	/* Custom protocol used in transactions to telecomkey.com
	 *
	 * Not idea what it is, exactly.
	 */

	if (MATCH(data->payload[0], 0x30, 0x30, 0x30, 0x30) &&
			data->payload_len[0] == 8)
		return true;
	if (MATCH(data->payload[1], 0x30, 0x30, 0x30, 0x30) &&
			data->payload_len[1] == 8)
		return true;

	return false;

}

static inline bool match_pptp_payload(uint32_t payload, uint32_t len) {

	if (len != 156)
		return false;

	if (!MATCH(payload, 0x00, 0x9c, 0x00, 0x01))
		return false;

	return true;

}

static inline bool match_pptp(lpi_data_t *data) {

	if (!match_pptp_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_pptp_payload(data->payload[1], data->payload_len[1]))
		return false;
	return true;

}

static inline bool match_openvpn_handshake(uint32_t payload, uint32_t len) {

	uint16_t pktlen = ntohs((uint16_t)payload);

	/* First two bytes are the length of the packet (not including the
	 * length) */
	if (pktlen + 2 != len)
		return false;
	
	/* Handshake packets have opcodes of either 7 or 8 and key IDs of 
	 * zero, so the third byte is either 0x38 or 0x40 */

	/* Ref: http://tinyurl.com/37tt3xe */

	if (MATCH(payload, ANY, ANY, 0x38, ANY))
		return true;
	if (MATCH(payload, ANY, ANY, 0x40, ANY))
		return true;


	return false;

}

static inline bool match_openvpn(lpi_data_t *data) {

	if (!match_openvpn_handshake(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_openvpn_handshake(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static inline bool match_xunlei(lpi_data_t *data) {

        /*
        if (match_str_both(data, "\x3c\x00\x00\x00", "\x3c\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x39\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x3d\x00\x00\x00", "\x3a\x00\x00\x00"))
                return true;
        */

        if (match_str_both(data, "\x29\x00\x00\x00", "\x29\x00\x00\x00"))
                return true;

        return false;
}

static inline bool match_afp(lpi_data_t *data) {

	/* Looking for a DSI header - command 4 is OpenSession */
	if (match_str_both(data, "\x00\x04\x00\x01", "\x01\x04\x00\x01"))
		return true;
	return false;

}

static inline bool match_smb(lpi_data_t *data) {

        /* SMB is often prepended with a NetBIOS session service header.
         * It's easiest for us to treat it as a four byte length field (it
         * is actually a bit more complicated than that, but all other fields
         * tend to be zero anyway)
         *
         * More details at http://lists.samba.org/archive/samba-technical/2003-January/026283.html
         */

	if (data->server_port != 445 && data->client_port != 445)
		return false;

	if (!match_payload_length(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_payload_length(data->payload[1], data->payload_len[1]))
		return false;

        return true;

}

static inline bool match_hamachi(lpi_data_t *data) {

        /* All Hamachi messages that I've seen begin with a 4 byte length
         * field. Other protocols also do this, so I also check for the
         * default Hamachi port (12975)
         */
        if (!match_payload_length(data->payload[0], data->payload_len[0]))
                return false;

        if (!match_payload_length(data->payload[1], data->payload_len[1]))
                return false;

        if (data->server_port == 12975 || data->client_port == 12975)
                return true;

        return false;

}


static inline bool match_azureus(lpi_data_t *data) {

        /* Azureus begins all messages with a 4 byte length field. 
         * Unfortunately, it is not uncommon for other protocols to do the 
         * same, so I'm also forced to check for the default Azureus port
         * (27001)
         */

        if (!match_payload_length(data->payload[0], data->payload_len[0]))
                return false;

        if (!match_payload_length(data->payload[1], data->payload_len[1]))
                return false;

        if (data->server_port == 27001 || data->client_port == 27001)
                return true;

        return false;
}

static inline bool match_netbios(lpi_data_t *data) {

        uint32_t stated_len = 0;

        if (MATCH(data->payload[0], 0x81, 0x00, ANY, ANY)) {
                stated_len = ntohl(data->payload[0]) & 0xffff;
                if (stated_len == data->payload_len[0] - 4)
                        return true;
        }

        if (MATCH(data->payload[1], 0x81, 0x00, ANY, ANY)) {
                stated_len = ntohl(data->payload[1]) & 0xffff;
                if (stated_len == data->payload_len[1] - 4)
                        return true;
        }

        return false;
}

inline bool match_emule(lpi_data_t *data) {
        /* Check that payload begins with e3 or c5 in both directions before 
         * classifying as eMule */
        /* (I noticed that most emule(probably) flows began with "e3 xx 00 00" 
         * or "c5 xx 00 00", perhaps is worth looking into... Although I 
         * couldn't find anything about emule packets) */
        
	if (data->payload_len[0] < 4 && data->payload_len[1] < 4)
		return false;
	
	if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00))
                return true;

        if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xc5, ANY, 0x00, 0x00))
                return true;

        /* XXX I haven't seen any obviously legit emule that starts with c5
         * in both directions */
        /*
        if (MATCH(data->payload[0], 0xc5, ANY, ANY, ANY) &&
            MATCH(data->payload[1], 0xc5, ANY, ANY, ANY))
                return true;
        */

        if (MATCH(data->payload[0], 0xc5, ANY, 0x00, 0x00) &&
            MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00))
                return true;

        if (MATCH(data->payload[0], 0xe3, ANY, 0x00, 0x00) &&
                data->payload_len[1] == 0)
                return true;

        if (MATCH(data->payload[1], 0xe3, ANY, 0x00, 0x00) &&
                data->payload_len[0] == 0)
                return true;


        return false;
}

static inline bool match_rdp(lpi_data_t *data) {

        uint32_t stated_len = 0;

        /* RDP is transported via TPKT
         *
         * TPKT header is 03 00 + 2 bytes of length (including the TPKT header)
         */

        if ((!MATCH(data->payload[0], 0x03, 0x00, ANY, ANY)) &&
                (!MATCH(data->payload[1], 0x03, 0x00, ANY, ANY))) {
                return false;
        }

        stated_len = ntohl(data->payload[0]) & 0xffff;
        if (stated_len != data->payload_len[0])
                return false;

        stated_len = ntohl(data->payload[1]) & 0xffff;
        if (stated_len != data->payload_len[1])
                return false;

        return true;

}

static inline bool match_http_tunnel(lpi_data_t *data) {

        if (match_str_both(data, "CONN", "HTTP")) return true;

        if (MATCHSTR(data->payload[0], "CONN") && data->payload_len[1] == 0)
                return true;

        if (MATCHSTR(data->payload[1], "CONN") && data->payload_len[0] == 0)
                return true;

        return false;
}

/* Rules adapted from l7-filter */
static inline bool match_telnet_pattern(uint32_t payload) {

	/* Sadly we cannot use a simple MATCH, because we're looking for
	 * two 0xff characters, which happens to be the same value as ANY.
	 */

	if ((payload & 0xff0000ff) != (0xff0000ff))
		return false;
	
	if (MATCH(payload, ANY, 0xfb, ANY, ANY))
		return true; 
	if (MATCH(payload, ANY, 0xfc, ANY, ANY))
		return true; 
	if (MATCH(payload, ANY, 0xfd, ANY, ANY))
		return true; 
	if (MATCH(payload, ANY, 0xfe, ANY, ANY))
		return true; 

	return false;
}

static inline bool match_telnet(lpi_data_t *data) {
	
	if (match_telnet_pattern(data->payload[0]))
		return true;
	if (match_telnet_pattern(data->payload[1]))
		return true;
	return false;
	
}

/* 16 03 00 X is an SSLv3 handshake */
static inline bool match_ssl3_handshake(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len == 1 && MATCH(payload, 0x16, 0x00, 0x00, 0x00))
		return true;
	if (MATCH(payload, 0x16, 0x03, 0x00, ANY))
		return true;
	return false;
}

/* 16 03 01 X is an TLS handshake */
static inline bool match_tls_handshake(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	if (len == 1 && MATCH(payload, 0x16, 0x00, 0x00, 0x00))
		return true;
	if (MATCH(payload, 0x16, 0x03, 0x01, ANY))
		return true;
	return false;
}

/* SSLv2 handshake - the ANY byte in the 0x80 payload is actually the length of the payload - 2. */
static inline bool match_ssl2_handshake(uint32_t payload, uint32_t len) {
        uint32_t stated_len = 0;
        
	if (!MATCH(payload, 0x80, ANY, 0x01, 0x03)) 
		return false;
        stated_len = (ntohl(payload) & 0xff0000) >> 16;
        if (stated_len == len - 2)
        	return true;
	return false;
}

static inline bool match_tls_content(uint32_t payload, uint32_t len) {
	if (MATCH(payload, 0x17, 0x03, 0x01, ANY))
		return true;
	return false;
}

static inline bool match_ssl(lpi_data_t *data) {


	if (match_ssl3_handshake(data->payload[0], data->payload_len[0]) &&
			match_ssl3_handshake(data->payload[1], data->payload_len[1]))
		return true;

	if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
			match_tls_handshake(data->payload[1], data->payload_len[1]))
		return true;
	
	if (match_ssl3_handshake(data->payload[0], data->payload_len[0]) &&
			match_tls_handshake(data->payload[1], data->payload_len[1]))
		return true;

	if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
			match_ssl3_handshake(data->payload[1], data->payload_len[1]))
		return true;
	/* Seems we can sometimes skip the full handshake and start on the data
	 * right away (as indicated by 0x17) - for now, I've only done this for TLS */
	if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
			match_tls_content(data->payload[1], data->payload_len[1]))
		return true;
	if (match_tls_handshake(data->payload[1], data->payload_len[1]) &&
			match_tls_content(data->payload[0], data->payload_len[0]))
		return true;


	if ((match_tls_handshake(data->payload[0], data->payload_len[0]) ||
			match_ssl3_handshake(data->payload[0], data->payload_len[0])) &&
			match_ssl2_handshake(data->payload[1], data->payload_len[1]))
		return true;
	
	if ((match_tls_handshake(data->payload[1], data->payload_len[1]) ||
			match_ssl3_handshake(data->payload[1], data->payload_len[1])) &&
			match_ssl2_handshake(data->payload[0], data->payload_len[0]))
		return true;

	if (data->payload_len[0] == 0 && match_ssl2_handshake(data->payload[1], data->payload_len[1]))
		return true;
	if (data->payload_len[1] == 0 && match_ssl2_handshake(data->payload[0], data->payload_len[0]))
		return true;

        return false;
}

static inline bool match_msnc_transfer(lpi_data_t *data) {

	if (!(data->payload_len[0] == 4 && data->payload_len[1] == 4))
		return false;
	
	if (match_str_both(data, "\x30\x00\x00\x00", "\x04\x00\x00\x00"))
		return true;

	return false;

}

static inline bool match_mysql(lpi_data_t *data) {

        uint32_t stated_len = 0;

        if (data->payload_len[0] == 0 && data->payload_len[1] == 0)
                return false;

        stated_len = (data->payload[0] & 0xffffff);
        if (data->payload_len[0] > 0 && stated_len != data->payload_len[0] - 4)
                return false;

        stated_len = (data->payload[1] & 0xffffff);
        if (data->payload_len[1] > 0 && stated_len != data->payload_len[1] - 4)
                return false;

        if (MATCH(data->payload[0], ANY, ANY, ANY, 0x00) &&
                        MATCH(data->payload[1], ANY, ANY, ANY, 0x01))
                return true;

        if (MATCH(data->payload[1], ANY, ANY, ANY, 0x00) &&
                        MATCH(data->payload[0], ANY, ANY, ANY, 0x01))
                return true;

	/* Need to enforce some sort of port checking here */
	if (data->server_port != 3306 && data->client_port != 3306)
		return false;

        if (MATCH(data->payload[0], ANY, ANY, ANY, 0x00) &&
                data->payload_len[1] == 0)
                return true;

        if (MATCH(data->payload[1], ANY, ANY, ANY, 0x00) &&
                data->payload_len[0] == 0)
                return true;

        return false;
}

static inline bool match_tds(lpi_data_t *data) {

        uint32_t stated_len = 0;

        if (MATCH(data->payload[0], 0x04, 0x01, ANY, ANY) &&
                        MATCH(data->payload[1], 0x12, 0x01, ANY, ANY)) {

                /* Check both lengths */

                stated_len = (ntohl(data->payload[0]) & 0xffff);
                if (stated_len != data->payload_len[0])
                        return false;

                stated_len = (ntohl(data->payload[1]) & 0xffff);
                if (stated_len != data->payload_len[1])
                        return false;

                return true;
        }


        if (MATCH(data->payload[1], 0x04, 0x01, ANY, ANY) &&
                        MATCH(data->payload[0], 0x12, 0x01, ANY, ANY)) {

                /* Check both lengths */

                stated_len = (ntohl(data->payload[0]) & 0xffff);
                if (stated_len != data->payload_len[0])
                        return false;

                stated_len = (ntohl(data->payload[1]) & 0xffff);
                if (stated_len != data->payload_len[1])
                        return false;

                return true;
        }

        return false;
}

static inline bool match_notes_rpc(lpi_data_t *data) {

        /* Notes RPC is a proprietary protocol and I haven't been able to
         * find anything to confirm or disprove any of this. 
         *
         * As a result, this rule is pretty iffy as it is based on a bunch
         * of flows observed going to 1 server using port 1352. There is
         * no documented basis for this (unlike most other rules)
         */

        if (!match_str_either(data, "\x78\x00\x00\x00"))
                return false;

        if (MATCH(data->payload[0], ANY, ANY, 0x00, 0x00) &&
                        MATCH(data->payload[1], ANY, ANY, 0x00, 0x00))
                return true;

        return false;

}

static inline bool match_invalid(lpi_data_t *data) {

        /* I'm using invalid as a category for flows where both halves of
         * the connection are clearly speaking different protocols,
         * e.g. trying to do HTTP tunnelling via an SMTP server
         */

        /* SOCKSv4 via FTP or SMTP 
         *
         * The last two octets '\x00\x50' is the port number - in this case
         * I've hard-coded it to be 80 */
        if (match_str_both(data, "220 ", "\x04\x01\x00\x50"))
                return true;

        /* SOCKSv5 via FTP or SMTP */
        if (match_str_both(data, "220 ", "\x05\x01\x00\x00"))
                return true;

        /* HTTP tunnelling via FTP or SMTP */
        if (match_str_both(data, "220 ", "CONN"))
                return true;

	/* Trying to send HTTP commands to FTP or SMTP servers */
	if (match_str_both(data, "220 ", "GET "))
		return true;

	/* People trying to do Bittorrent to an actual HTTP server, rather than
	 * someone peering on port 80 */

	if (match_str_either(data, "HTTP") && 
			match_chars_either(data, 0x13, 'B', 'i', 't'))
		return true;
	

        return false;
}

static inline bool match_trackmania(lpi_data_t *data) {

	if (data->server_port != 3450 && data->client_port != 3450)
		return false;
	
	if (!match_str_both(data, "\x23\x00\x00\x00", "\x13\x00\x00\x00"))
		return false;
	
        if (!match_payload_length(ntohl(data->payload[0]), 
			data->payload_len[0]))
                return false;

        if (!match_payload_length(ntohl(data->payload[1]), 
			data->payload_len[1]))
                return false;

	return true;

}

static inline bool match_bittorrent_header(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	
	if (MATCH(payload, 0x13, 'B', 'i', 't'))
		return true;
	
	if (len == 2 && MATCH(payload, 0x13, 'B', 'i', 0x00))
		return true;

	return false;

}

static inline bool match_bittorrent(lpi_data_t *data) {

	if (!match_bittorrent_header(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_bittorrent_header(data->payload[1], data->payload_len[1]))
		return false;
	return true;

}

static inline bool match_file_header(uint32_t payload) {

	/* RIFF is a meta-format for storing AVI and WAV files */
	if (MATCHSTR(payload, "RIFF"))
		return true;

	/* MZ is a .exe file */
	if (MATCH(payload, 'M', 'Z', ANY, 0x00))
		return true;

	/* Ogg files */
	if (MATCHSTR(payload, "OggS"))
		return true;
	
	/* ZIP files */
	if (MATCH(payload, 'P', 'K', 0x03, 0x04))
		return true;

	/* MPEG files */
	if (MATCH(payload, 0x00, 0x00, 0x01, 0xba))
		return true;

	/* RAR files */
	if (MATCHSTR(payload, "Rar!"))
		return true;
	
	/* EBML */
	if (MATCH(payload, 0x1a, 0x45, 0xdf, 0xa3))
		return true;

	/* JPG */
	if (MATCH(payload, 0xff, 0xd8, ANY, ANY))
		return true;

	/* I'm also going to include PHP scripts in here */
	if (MATCH(payload, 0x3c, 0x3f, 0x70, 0x68))
		return true;

	/* Unix scripts */
	if (MATCH(payload, 0x23, 0x21, 0x2f, 0x62))
		return true;

	/* PDFs */
	if (MATCHSTR(payload, "%PDF"))
		return true;
	
	/* PNG */
	if (MATCH(payload, 0x89, 'P', 'N', 'G'))
		return true;

	/* HTML */
	if (MATCHSTR(payload, "<htm"))
		return true;

	/* 7zip */
	if (MATCH(payload, 0x37, 0x7a, 0xbc, 0xaf))
		return true;

	/* gzip  - may need to replace last two bytes with ANY */
	if (MATCH(payload, 0x1f, 0x8b, 0x08, 0x00))
		return true;

	/* XML */
	if (MATCHSTR(payload, "<!DO"))
		return true;

	/* FLAC */
	if (MATCHSTR(payload, "fLaC"))
		return true;

	/* MP3 */
	if (MATCH(payload, 'I', 'D', '3', 0x03))
		return true;

	/* RPM */
	if (MATCH(payload, 0xed, 0xab, 0xee, 0xdb))
		return true;

	/* Wz Patch */
	if (MATCHSTR(payload, "WzPa"))
		return true;

	return false;

}

static inline bool match_bulk_response(uint32_t payload, uint32_t len) {

	/* Most FTP-style transactions result in no packets being sent back
	 * to server (aside from ACKs) */

	if (len == 0)
		return true;
	
	/* However, there is at least one FTP client that sends some sort of
	 * sequence number back to the server - maybe allowing for resumption
	 * of paused transfers? 
	 *
	 * XXX This seems to be related to completely failing to implement the
	 * FTP protocol correctly. There is usually a flow preceding these
	 * flows that sends commands like "get" and "dir" to the server, 
	 * which are not actually part of the FTP protocol. Instead, these
	 * are often commands typed into FTP CLI clients that are converted
	 * into the appropriate FTP commands. No idea what software is doing
	 * this, but it is essentially emulating FTP so I'll keep it in here
	 * for now.
	 * */

	if (len == 4 && MATCH(payload, 0x00, 0x00, 0x02, 0x00))
		return true;
	return false;
	
}
	
/* Bulk download covers files being downloaded through a separate channel,
 * like FTP data. We identify these by observing file type identifiers at the
 * start of the packet. This is not a protocol in itself, but it's almost 
 * certainly FTP.
 */
static inline bool match_bulk_download(lpi_data_t *data) {	

	if (match_bulk_response(data->payload[1], data->payload_len[1]) &&
			match_file_header(data->payload[0]))
		return true;
	if (match_bulk_response(data->payload[0], data->payload_len[0]) &&
			match_file_header(data->payload[1]))
		return true;

	return false;
}

static inline bool match_postgresql(lpi_data_t *data) {

	/* Client start up messages start with a 4 byte length */
	/* Server auth requests start with 'R', followed by 4 bytes of length
	 *
	 * All auth requests tend to be quite small */

	if (ntohl(data->payload[0]) == data->payload_len[0])
	{
		if (MATCH(data->payload[1], 0x52, 0x00, 0x00, 0x00))
			return true;
	}
	
	if (ntohl(data->payload[1]) == data->payload_len[1])
	{
		if (MATCH(data->payload[0], 0x52, 0x00, 0x00, 0x00))
			return true;
	}

	return false;

}

static inline bool match_ftp_command(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	/* There are lots of valid FTP commands, but let's just limit this
	 * to ones we've observed for now */

	if (MATCHSTR(payload, "USER"))
		return true;
	if (MATCHSTR(payload, "QUIT"))
		return true;
	if (MATCHSTR(payload, "FEAT"))
		return true;
	if (MATCHSTR(payload, "HELP"))
		return true;
	if (MATCHSTR(payload, "user"))
		return true;

	/* This is invalid syntax, but clients using HOST seem to revert to
	 * sane FTP commands once the server reports a syntax error */
	if (MATCHSTR(payload, "HOST"))
		return true;

	return false;

}

static inline bool match_ftp_reply_code(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;
	
	if (MATCHSTR(payload, "220 "))
		 return true;
	if (MATCHSTR(payload, "220-"))
		 return true;
	return false;
}


static inline bool match_ftp_control(lpi_data_t *data) {

	if (data->server_port == 25 || data->client_port == 25)
		return false;

	if (match_ftp_reply_code(data->payload[0], data->payload_len[0])) {
		if (match_ftp_command(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_ftp_reply_code(data->payload[1], data->payload_len[1])) {
		if (match_ftp_command(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;
}
	
static inline bool match_http_request(uint32_t payload, uint32_t len) {

        /* HTTP requests - some of these are MS-specific extensions */
	if (len == 0)
		return true;

        if (MATCHSTR(payload, "GET ")) return true; 
		
        if (MATCHSTR(payload, "POST")) return true;
        if (MATCHSTR(payload, "HEAD")) return true;
        if (MATCHSTR(payload, "PUT ")) return true;
        if (MATCHSTR(payload, "DELE")) return true;
        if (MATCHSTR(payload, "OPTI")) return true;
        if (MATCHSTR(payload, "PROP")) return true;
        if (MATCHSTR(payload, "MKCO")) return true;
        if (MATCHSTR(payload, "LOCK")) return true;
        if (MATCHSTR(payload, "POLL")) return true;
        if (MATCHSTR(payload, "SEAR")) return true;
	if (MATCHSTR(payload, "auth")) return true;

	return false;

}

static inline bool match_http_response(uint32_t payload, uint32_t len) {
	
	if (len == 0)
		return true;
        if (MATCHSTR(payload, "HTTP")) {
		return true;	
	}
	
	return false;

	
}

static inline bool valid_http_port(lpi_data_t *data) {
	/* Must be on a known HTTP port - designed to filter 
	 * out P2P protos that use HTTP.
	 *
	 * XXX If this doesn't work well, get rid of it!
	*/
	if (data->server_port == 80 || data->client_port == 80)
		return true;
	if (data->server_port == 8080 || data->client_port == 8080)
		return true;
	if (data->server_port == 8081 || data->client_port == 8081)
		return true;

	/* If port 443 responds, we want it to be counted as genuine
	 * HTTP, rather than a bad port scenario */
	if (data->server_port == 443 || data->client_port == 443) {
		if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
			return true;
	}

	return false;

}

/* Trying to match stuff like KaZaA and Gnutella transfers that base their
 * communications on HTTP */
static inline bool match_p2p_http(lpi_data_t *data) {

	/* Must not be on a known HTTP port
	 *
	 * XXX I know that people will still try to use port 80 for their
	 * warezing, but we want to at least try and get the most obvious 
	 * HTTP-based P2P
	 */	
	if (valid_http_port(data))
		return false;

	if (match_str_both(data, "GET ", "HTTP"))
		return true;
	
	return false;

}


static inline bool match_http(lpi_data_t *data) {

	if (!valid_http_port(data))
		return false;

	if (match_http_request(data->payload[0], data->payload_len[0])) {
		if (match_http_response(data->payload[1], data->payload_len[1]))
			return true;
		if (match_http_request(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_http_request(data->payload[1], data->payload_len[1])) {
		if (match_http_response(data->payload[0], data->payload_len[0]))
			return true;
	}
	

	return false;
		

}

lpi_protocol_t guess_tcp_protocol(lpi_data_t *proto_d)
{
        
	if (proto_d->payload_len[0] == 0 && proto_d->payload_len[1] == 0)
		return LPI_PROTO_NO_PAYLOAD;
	
	
	/* DirectConnect */
        /* $MyN seemed best to check for - might have to check for $max and
         * $Sup as well */
        /* NOTE: Some people seem to use DC to connect to port 80 and get
         * HTTP responses. At this stage, I'd rather that fell under DC rather
         * than HTTP, so we need to check for this before we check for HTTP */
        if (match_str_either(proto_d, "$MyN")) return LPI_PROTO_DC;
        if (match_str_either(proto_d, "$Sup")) return LPI_PROTO_DC;
        if (match_str_either(proto_d, "$Loc")) return LPI_PROTO_DC;

        /* Gnutella */
        if (match_str_either(proto_d, "GNUT")) return LPI_PROTO_GNUTELLA;
        /*  GIV signifies a Gnutella upload, which is typically done via
         *  HTTP. This means we need to match this before checking for HTTP */
        if (match_str_either(proto_d, "GIV ")) return LPI_PROTO_GNUTELLA;

        /* Tunnelling over HTTP */
        if (match_http_tunnel(proto_d)) return LPI_PROTO_HTTP_TUNNEL;
	
	/* Shoutcast client requests */
	if (match_str_both(proto_d, "GET ", "ICY "))
		return LPI_PROTO_SHOUTCAST;

        /* HTTP response */
	if (match_http(proto_d)) return LPI_PROTO_HTTP;
	if (match_p2p_http(proto_d)) return LPI_PROTO_P2P_HTTP;
	if (match_http_badport(proto_d)) return LPI_PROTO_HTTP_BADPORT;

        /* SMTP */
        if (match_smtp(proto_d)) return LPI_PROTO_SMTP;

        /* SSH */
        if (match_str_either(proto_d, "SSH-")) return LPI_PROTO_SSH;
        if (match_str_either(proto_d, "QUIT") && proto_d->server_port == 22)
                return LPI_PROTO_SSH;

        /* POP3 */
        if (match_chars_either(proto_d, '+','O','K',ANY))
                return LPI_PROTO_POP3;

	/* Harveys - a seemingly custom protocol used by Harveys Real
	 * Estate to transfer photos. Common in ISP C traces */
	if (match_str_both(proto_d, "77;T", "47;T"))
		return LPI_PROTO_HARVEYS;

        /* IMAP seems to start with "* OK" */
        if (match_str_either(proto_d, "* OK")) return LPI_PROTO_IMAP;

        /* Bittorrent is 0x13 B i t */
        if (match_bittorrent(proto_d)) return LPI_PROTO_BITTORRENT;

        if (match_str_either(proto_d, "@RSY")) return LPI_PROTO_RSYNC;

	/* Pando P2P protocol */
	if (match_str_either(proto_d, "\x0ePan"))
		return LPI_PROTO_PANDO;

	if (match_bulk_download(proto_d)) return LPI_PROTO_FTP_DATA;

        /* Newsfeeds */
        if (match_str_either(proto_d, "mode")) return LPI_PROTO_NNTP;
        if (match_str_either(proto_d, "MODE")) return LPI_PROTO_NNTP;
        if (match_str_either(proto_d, "GROU")) return LPI_PROTO_NNTP;
        if (match_str_either(proto_d, "grou")) return LPI_PROTO_NNTP;

        if (match_str_both(proto_d, "AUTH", "200 ")) return LPI_PROTO_NNTP;
        if (match_str_both(proto_d, "AUTH", "201 ")) return LPI_PROTO_NNTP;
        if (match_str_both(proto_d, "AUTH", "200-")) return LPI_PROTO_NNTP;
        if (match_str_both(proto_d, "AUTH", "201-")) return LPI_PROTO_NNTP;

        /* IRC */
        if (match_str_either(proto_d, "PASS")) return LPI_PROTO_IRC;
        if (match_str_either(proto_d, "NICK")) return LPI_PROTO_IRC;

        /* Razor server contacts (ie SpamAssassin) */
        if (match_chars_either(proto_d, 's', 'n', '=', ANY))
                return LPI_PROTO_RAZOR;

        /* Virus definition updates from CA are delivered via FTP */
        if (match_str_either(proto_d, "Viru")) return LPI_PROTO_FTP_DATA;

        /* FTP */
        if (match_ftp_data(proto_d)) return LPI_PROTO_FTP_DATA;
        if (match_ftp_control(proto_d)) return LPI_PROTO_FTP_CONTROL;
		
        /* MSN typically starts with ANS USR or VER */
        if (match_str_either(proto_d, "ANS ")) return LPI_PROTO_MSN;
        if (match_str_either(proto_d, "USR ")) return LPI_PROTO_MSN;
        if (match_str_either(proto_d, "VER ")) return LPI_PROTO_MSN;

	if (match_telnet(proto_d)) return LPI_PROTO_TELNET;

        /* Yahoo messenger starts with YMSG */
        if (match_str_either(proto_d, "YMSG")) return LPI_PROTO_YAHOO;
        /* Some flows start with YAHO - I'm going to go with my gut instinct */
        if (match_str_either(proto_d, "YAHO")) return LPI_PROTO_YAHOO;

        /* RTSP starts with RTSP */
        if (match_str_either(proto_d, "RTSP")) return LPI_PROTO_RTSP;

        /* A particular protocol that only seems to be used by NCSoft */
        if (match_chars_either(proto_d, 0x00, 0x05, 0x0c, 0x00))
                return LPI_PROTO_NCSOFT;

        /* Azureus Extension */
        //if (match_azureus(proto_d)) return LPI_PROTO_AZUREUS;

	if (match_trackmania(proto_d)) return LPI_PROTO_TRACKMANIA;

        /* SMB */
        if (match_smb(proto_d)) return LPI_PROTO_SMB;

        /* NetBIOS Session */
        if (match_netbios(proto_d)) return LPI_PROTO_NETBIOS;

        /* SSL starts with 16 03, but if on port 443 it's HTTPS */
        if (match_ssl(proto_d)) {
                if (proto_d->server_port == 443 ||
				proto_d->client_port == 443)
                        return LPI_PROTO_HTTPS;
		else if (proto_d->server_port == 993 || 
				proto_d->client_port == 993)
			return LPI_PROTO_IMAPS;
                else
                        return LPI_PROTO_SSL;
        }

        /* RDP */
        if (match_rdp(proto_d)) return LPI_PROTO_RDP;

        /* Citrix ICA  */
        if (match_chars_either(proto_d, 0x7f, 0x7f, 0x49, 0x43))
                return LPI_PROTO_ICA;

        /* RPC exploit */
        if (match_chars_either(proto_d, 0x05, 0x00, 0x0b, 0x03))
                return LPI_PROTO_RPC_SCAN;

        /* Yahoo Webcam */
        if (match_str_either(proto_d, "<SND"))
                return LPI_PROTO_YAHOO_WEBCAM;
        if (match_str_either(proto_d, "<REQ"))
                return LPI_PROTO_YAHOO_WEBCAM;
        if (match_chars_either(proto_d, 0x0d, 0x00, 0x05, 0x00))
                return LPI_PROTO_YAHOO_WEBCAM;

	/* Steam TCP download */
	if (match_steam(proto_d)) return LPI_PROTO_STEAM;

        /* ID Protocol */
        /* TODO: Starts with only digits - request matches the response  */
        /* 20 3a 20 55 is an ID protocol error, I think */
        if (match_str_either(proto_d, " : U")) return LPI_PROTO_ID;


        /* ar archives, typically .deb files */
        if (match_str_either(proto_d, "!<ar")) return LPI_PROTO_AR;

        /* All-seeing Eye - Yahoo Games */
        if (match_str_either(proto_d, "EYE1")) return LPI_PROTO_EYE;

        /* [Shane is] fairly sure this will match the ARES p2p protocol */
        if (match_str_either(proto_d, "ARES")) return LPI_PROTO_ARES;

        /* Some kind of Warcraft 3 error message, at a guess */
        if (match_chars_either(proto_d, 0xf7, 0x37, 0x12, 0x00))
                return LPI_PROTO_WARCRAFT3;

        /* XXX - I have my doubts about these rules */
#if 0   
        /* Warcraft 3 packets all begin with 0xf7 */
        if (match_chars_either(proto_d, 0xf7, 0xf7, ANY, ANY)) 
                return LPI_PROTO_WARCRAFT3;
        /* Another Warcraft 3 example added by Donald Neal */
        if (match_chars_either(proto_d, 0xf7, 0x1e, ANY, 0x00))
                return LPI_PROTO_WARCRAFT3;
#endif

        /* RFB */
        if (match_str_either(proto_d, "RFB ")) return LPI_PROTO_RFB;

	/* Flash player stuff - cross-domain policy etc */
	if (match_str_either(proto_d, "<cro") && 
			(match_str_either(proto_d, "<msg") || 
			match_str_either(proto_d, "<pol"))) {
		return LPI_PROTO_FLASH;
	}


        /* KMS */
        /* Bloody microsoft doesn't tell us a damn thing so I have to hax a 
         * definition together */
        /*
        if (match_chars_either(proto_d, 0xbc, 0xef, ANY, ANY))
                 return LPI_PROTO_KMS;
        */

        /* DNS */
        if (match_dns(proto_d))
                return LPI_PROTO_DNS;
	if (match_dns_zone_transfer(proto_d))
		return LPI_PROTO_DNS;

	/* Incoming source connections - other direction sends a plain-text
	 * password */
	if (match_chars_either(proto_d, 'O', 'K', '2', 0x0d))
		return LPI_PROTO_SHOUTCAST;

        /* SIP */
        if (match_str_both(proto_d, "SIP/", "REGI"))
                return LPI_PROTO_SIP;
        /* Non-RFC SIP added by Donald Neal, June 2008 */
        if (match_str_either(proto_d, "SIP-") &&
                match_chars_either(proto_d, 'R', ' ', ANY, ANY))
                return LPI_PROTO_SIP;

        /* Raw XML */
        if (match_str_either(proto_d, "<?xm")) return LPI_PROTO_TCP_XML;
        if (match_str_either(proto_d, "<iq ")) return LPI_PROTO_TCP_XML;

        /* Mzinga */
        if (match_str_either(proto_d, "PCHA")) return LPI_PROTO_MZINGA;

        /* Bittorrent extensions */
        if (match_bitextend(proto_d)) return LPI_PROTO_BITEXT;

        /* Gokuchat Instant Messenger */
        if (match_str_both(proto_d, "ok:g", "baut"))
                return LPI_PROTO_GOKUCHAT;
        if (match_str_both(proto_d, "ok:w", "baut"))
                return LPI_PROTO_GOKUCHAT;

	if (match_str_either(proto_d, "PUSH")) return LPI_PROTO_TIP;

        /* DXP */
        if (match_chars_either(proto_d, 0xb0, 0x04, 0x15, 0x00))
                return LPI_PROTO_DXP;

        //if (match_str_either(proto_d, "NCPT")) return LPI_PROTO_NCPT;

        /* Blizzard - possibly WoW? */
        if (match_blizzard(proto_d)) return LPI_PROTO_BLIZZARD;

        /* MSNV */
        if (match_str_both(proto_d, "\x1\x1\x0\x70", "\x0\x1\x0\x64"))
                return LPI_PROTO_MSNV;

        /* Mitglieder Trojan - often used to relay spam over SMTP */
        if (match_chars_either(proto_d, 0x04, 0x01, 0x00, 0x19))
                return LPI_PROTO_MITGLIEDER;

	if (match_message4u(proto_d)) return LPI_PROTO_M4U;

	if (match_wow(proto_d)) return LPI_PROTO_WOW;

	if (match_rbls(proto_d)) return LPI_PROTO_RBLS;

        /* Xunlei */
        if (match_xunlei(proto_d)) return LPI_PROTO_XUNLEI;

        /* Hamachi - Proprietary VPN */
        if (match_hamachi(proto_d)) return LPI_PROTO_HAMACHI;

        /* I *think* this is TOR, but I haven't been able to confirm properly */
        if (match_chars_either(proto_d, 0x3d, 0x00, 0x00, 0x00) &&
                (proto_d->payload_len[0] == 4 || proto_d->payload_len[1] == 4))
                return LPI_PROTO_TOR;

	if (match_conquer_online(proto_d)) return LPI_PROTO_CONQUER;

	if (match_openvpn(proto_d)) return LPI_PROTO_OPENVPN;

	if (match_pptp(proto_d)) return LPI_PROTO_PPTP;

	if (match_telecomkey(proto_d)) return LPI_PROTO_TELECOMKEY;

	if (match_msnc_transfer(proto_d)) return LPI_PROTO_MSNC;

	if (match_afp(proto_d)) return LPI_PROTO_AFP;

	if (match_pdbox(proto_d)) return LPI_PROTO_PDBOX;
	
	/* Unknown protocol that seems to put the packet length in the first
         * octet - XXX Figure out what this is! */
        //if (match_length_proto(proto_d)) return LPI_PROTO_LENGTH;

        if (match_mysql(proto_d)) return LPI_PROTO_MYSQL;

	if (match_postgresql(proto_d)) return LPI_PROTO_POSTGRESQL;

        if (match_tds(proto_d)) return LPI_PROTO_TDS;

        if (match_notes_rpc(proto_d)) return LPI_PROTO_NOTES_RPC;

	if (match_rtmp(proto_d)) return LPI_PROTO_RTMP;

	if (match_yahoo_error(proto_d)) return LPI_PROTO_YAHOO_ERROR;

	if (match_imesh(proto_d)) return LPI_PROTO_IMESH;

        /* eMule */
        if (match_emule(proto_d)) return LPI_PROTO_EMULE;

        /* Check for any weird broken behaviour, i.e. trying to tunnel via
         * the wrong server */
        if (match_invalid(proto_d)) return LPI_PROTO_INVALID;

        return LPI_PROTO_UNKNOWN;
}

