
#include "libprotoident.h"
#include "proto_common.h"
#include "proto_tcp.h"

static inline bool match_smtp(lpi_data_t *data) {


	/* Match 421 reply codes */	
	if (data->payload_len[0] == 0 &&
			MATCH(data->payload[1], '4', '2', '1', ' '))
		return true;
	if (data->payload_len[1] == 0 &&
			MATCH(data->payload[0], '4', '2', '1', ' '))
		return true;
	
	
	if (data->payload_len[0] == 1) {
		if (!MATCH(data->payload[0], '2', 0x00, 0x00, 0x00))
			return false;
	} else if (data->payload_len[1] == 1) {
		if (!MATCH(data->payload[1], '2', 0x00, 0x00, 0x00))
			return false;
	}
	else if (!match_str_either(data, "220 ") && !match_str_either(data, "220-"))
		return false;
	
	if (match_str_either(data, "EHLO")) return true;
	if (match_str_either(data, "ehlo")) return true;
	if (match_str_either(data, "HELO")) return true;
	if (match_str_either(data, "helo")) return true;
	if (match_str_either(data, "NOOP")) return true;
	if (match_str_either(data, "XXXX")) return true;

	if (match_str_either(data, "QUIT") && data->server_port == 25)
		return true;
	if (match_str_either(data, "quit") && data->server_port == 25)
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

inline bool match_dns(lpi_data_t *data) {

        if ((data->payload[0] & 0x0079ffff) != (data->payload[1] & 0x0079ffff))
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

static inline bool match_smb(lpi_data_t *data) {

        /* SMB is often prepended with a NetBIOS session service header.
         * It's easiest for us to treat it as a four byte length field (it
         * is actually a bit more complicated than that, but all other fields
         * tend to be zero anyway)
         *
         * More details at http://lists.samba.org/archive/samba-technical/2003-January/026283.html
         */

        return false;

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

static inline bool match_smtp_scan(lpi_data_t *data) {

        if (MATCHSTR(data->payload[0], "220 ") && data->payload_len[1] == 0)
                return true;
        if (MATCHSTR(data->payload[1], "220 ") && data->payload_len[0] == 0)
                return true;
        return false;
}

/* Rules adapted from l7-filter */
static inline bool match_telnet(lpi_data_t *data) {
	if (match_chars_either(data, 0xff, 0xfb, ANY, 0xff))
		return true; 
	if (match_chars_either(data, 0xff, 0xfc, ANY, 0xff))
		return true; 
	if (match_chars_either(data, 0xff, 0xfd, ANY, 0xff))
		return true; 
	if (match_chars_either(data, 0xff, 0xfe, ANY, 0xff))
		return true; 
	return false;
}

/* 16 03 00 X is an SSLv3 handshake */
static inline bool match_ssl3_handshake(uint32_t payload, uint32_t len) {

	if (len == 1 && MATCH(payload, 0x16, 0x00, 0x00, 0x00))
		return true;
	if (MATCH(payload, 0x16, 0x03, 0x00, ANY))
		return true;
	return false;
}

/* 16 03 01 X is an TLS handshake */
static inline bool match_tls_handshake(uint32_t payload, uint32_t len) {

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

        return false;
}

static inline bool match_trackmania(lpi_data_t *data) {

	if (data->server_port != 3450 && data->client_port != 3450)
		return false;
	
	if (!match_str_both(data, "\x23\x00\x00\x00", "\x13\x00\x00\x00"))
		return false;
	
        if (!match_payload_length(data->payload[0], data->payload_len[0]))
                return false;

        if (!match_payload_length(data->payload[1], data->payload_len[1]))
                return false;

	return true;

}
	
/* Bulk download covers files being downloaded through a separate channel,
 * like FTP data. We identify these by observing file type identifiers at the
 * start of the packet. This is not a protocol in itself - we cannot identify
 * the protocol, but we don't want to count this as "unknown" either.
 */
static inline bool match_bulk_download(lpi_data_t *data) {	

	/* For now, we also have a rule that there can only be traffic one
	 * way, as all the protocol control is over another connection */
	if (data->payload_len[0] > 0 && data->payload_len[1] > 0)
		return false;

	/* RIFF is a meta-format for storing AVI and WAV files */
	if (match_str_either(data, "RIFF"))
		return true;

	/* MZ is a .exe file */
	if (match_chars_either(data, 'M', 'Z', ANY, 0x00))
		return true;

	/* Ogg files */
	if (match_str_either(data, "OggS"))
		return true;
	
	/* ZIP files */
	if (match_chars_either(data, 'P', 'K', 0x03, 0x04))
		return true;

	/* MPEG files */
	if (match_chars_either(data, 0x00, 0x00, 0x01, 0xba))
		return true;

	/* RAR files */
	if (match_str_either(data, "Rar!"))
		return true;

	return false;
}
	
static inline bool match_http_request(lpi_data_t *data) {

        /* HTTP requests */

        if (match_str_either(data, "GET ")) {
		
		/* Must be on a known HTTP port - designed to filter 
		 * out P2P protos that use HTTP.
		 *
		 * XXX If this doesn't work well, get rid of it!
		*/
		if (data->server_port == 80 || data->client_port == 80)
			return true;
		if (data->server_port == 8080 || data->client_port == 8080)
			return true;
	}
        if (match_str_either(data, "POST")) return true;
        if (match_str_either(data, "HEAD")) return true;
        if (match_str_either(data, "PUT ")) return true;

	return false;

}

static inline bool match_http_response(lpi_data_t *data) {
        if (match_str_either(data, "HTTP")) {
		
		/* Must be on a known HTTP port - designed to filter 
		 * out P2P protos that use HTTP.
		 *
		 * XXX If this doesn't work well, get rid of it!
		*/
		if (data->server_port == 80 || data->client_port == 80)
			return true;
		if (data->server_port == 8080 || data->client_port == 8080)
			return true;
	}
	
	return false;

	
}

/* Trying to match stuff like KaZaA and Gnutella transfers that base their
 * communications on HTTP */
static inline bool match_p2p_http(lpi_data_t *data) {

	if (!match_str_both(data, "GET ", "HTTP"))
		return false;

	/* Must not be on a known HTTP port
	 *
	 * XXX I know that people will still try to use port 80 for their
	 * warezing, but we want to at least try and get the most obvious 
	 * HTTP-based P2P
	 */	
	if (data->server_port == 80 || data->client_port == 80)
		return false;
	if (data->server_port == 8080 || data->client_port == 8080)
		return false;

	return true;

}

lpi_protocol_t guess_tcp_protocol(lpi_data_t *proto_d)
{
        
	if (proto_d->payload_len[0] < 4 && proto_d->payload_len[1] < 4)
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

        /* HTTP response */
	if (match_http_response(proto_d)) return LPI_PROTO_HTTP;
	if (match_http_request(proto_d)) return LPI_PROTO_HTTP;

	if (match_p2p_http(proto_d)) return LPI_PROTO_P2P_HTTP;

        if (match_str_either(proto_d, "auth")) return LPI_PROTO_HTTP;
        /* Microsoft extensions to HTTP */
        if (match_str_either(proto_d, "SEAR")) return LPI_PROTO_HTTP_MS;
        if (match_str_either(proto_d, "POLL")) return LPI_PROTO_HTTP_MS;
        if (match_str_either(proto_d, "PROP")) return LPI_PROTO_HTTP_MS;

        /* SMTP */
        /*  55x reject codes */
        if (match_chars_either(proto_d, '5','5',ANY,' '))
                return LPI_PROTO_SMTPREJECT;
        if (match_chars_either(proto_d, '5','5',ANY,'-'))
                return LPI_PROTO_SMTPREJECT;
        if (match_chars_either(proto_d, '4','5','0',' '))
                return LPI_PROTO_SMTPREJECT;

        /*  SMTP Commands */
        if (match_smtp(proto_d)) return LPI_PROTO_SMTP;

        if (match_smtp_scan(proto_d)) return LPI_PROTO_SMTP_SCAN;

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
        if (match_str_either(proto_d, "\x13""Bit"))
                return LPI_PROTO_BITTORRENT;

        if (match_str_either(proto_d, "@RSY")) return LPI_PROTO_RSYNC;

	/* Pando P2P protocol */
	if (match_str_either(proto_d, "\x0ePan"))
		return LPI_PROTO_PANDO;

	if (match_bulk_download(proto_d)) return LPI_PROTO_TCP_BULK;

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
        if (match_str_either(proto_d, "FEAT")) return LPI_PROTO_FTP_CONTROL;
        if (match_str_both(proto_d, "USER", "220 "))
                return LPI_PROTO_FTP_CONTROL;
        if (match_str_both(proto_d, "USER", "220-"))
                return LPI_PROTO_FTP_CONTROL;

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
        if (match_azureus(proto_d)) return LPI_PROTO_AZUREUS;

	if (match_trackmania(proto_d)) return LPI_PROTO_TRACKMANIA;

        /* SMB */
        if (match_smb(proto_d)) return LPI_PROTO_SMB;

        /* NetBIOS Session */
        if (match_netbios(proto_d)) return LPI_PROTO_NETBIOS;

        /* SSL starts with 16 03, but if on port 443 it's HTTPS */
        if (match_ssl(proto_d)) {
                if (proto_d->server_port == 443)
                        return LPI_PROTO_HTTPS;
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

	/* Shoutcast client requests */
	if (match_str_both(proto_d, "GET ", "ICY "))
		return LPI_PROTO_SHOUTCAST;
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

        /* POP3 */
        if (match_str_either(proto_d, "USER")) return LPI_PROTO_POP3;

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

        /* Xunlei */
        if (match_xunlei(proto_d)) return LPI_PROTO_XUNLEI;

        /* Hamachi - Proprietary VPN */
        if (match_hamachi(proto_d)) return LPI_PROTO_HAMACHI;

        /* I *think* this is TOR, but I haven't been able to confirm properly */
        if (match_chars_either(proto_d, 0x3d, 0x00, 0x00, 0x00) &&
                (proto_d->payload_len[0] == 4 || proto_d->payload_len[1] == 4))
                return LPI_PROTO_TOR;

	if (match_conquer_online(proto_d)) return LPI_PROTO_CONQUER;
	
	/* Unknown protocol that seems to put the packet length in the first
         * octet - XXX Figure out what this is! */
        //if (match_length_proto(proto_d)) return LPI_PROTO_LENGTH;

        if (match_mysql(proto_d)) return LPI_PROTO_MYSQL;

        if (match_tds(proto_d)) return LPI_PROTO_TDS;

        if (match_notes_rpc(proto_d)) return LPI_PROTO_NOTES_RPC;

	if (match_rtmp(proto_d)) return LPI_PROTO_RTMP;

        /* eMule */
        if (match_emule(proto_d)) return LPI_PROTO_EMULE;

        /* Check for any weird broken behaviour, i.e. trying to tunnel via
         * the wrong server */
        if (match_invalid(proto_d)) return LPI_PROTO_INVALID;

        return LPI_PROTO_UNKNOWN;
}

