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

#include "libprotoident.h"
#include "proto_common.h"
#include "proto_tcp.h"

static inline bool match_cod_waw(lpi_data_t *data) {

	/* Call of Duty: World at War uses TCP port 3074 - the protocol isn't
	 * well documented, but traffic matching this pattern goes to known
	 * CoD servers */

	if (data->server_port != 3074 && data->client_port != 3074)
		return false;

	if (data->payload_len[0] != 4 || data->payload_len[1] != 4)
		return false;
	
	if (data->payload[0] != 0 || data->payload[1] != 0)
		return false;

	return true;

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

static inline bool match_clubbox(lpi_data_t *data) {

	if (!match_str_both(data, "\x00\x00\x01\x03", "\x00\x00\x01\x03"))
		return false;
	
	if (data->payload_len[0] == 36 && data->payload_len[1] == 28)
		return true;
	if (data->payload_len[1] == 36 && data->payload_len[0] == 28)
		return true;

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

static inline bool match_winmx(lpi_data_t *data) {

	if (match_str_either(data, "SEND")) {
		if (data->payload_len[0] == 1)
			return true;
		if (data->payload_len[1] == 1)
			return true;
	}
	if (match_chars_either(data, 'G', 'E', 'T', ANY)) {
		if (data->payload_len[0] == 1)
			return true;
		if (data->payload_len[1] == 1)
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




static inline bool match_mp2p(lpi_data_t *data) {

	/* Looking for STR, SIZ, MD5, GO!! */

	if (match_str_both(data, "STR ", "SIZ "))
		return true;
	if (MATCHSTR(data->payload[0], "STR ")) {
		if (data->payload_len[0] == 10 || data->payload_len[0] == 11)
			return true;
	}
	if (MATCHSTR(data->payload[1], "STR ")) {
		if (data->payload_len[1] == 10 || data->payload_len[1] == 11)
			return true;
	}

	return false;

}


static inline bool match_socks5_req(uint32_t payload, uint32_t len) {

	/* Just assume "no auth" method supported, for now */
	if (!(MATCH(payload, 0x05, 0x01, 0x00, 0x00)))
		return false;

	if (len != 3)
		return false;

	return true;
	
}

static inline bool match_socks5_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	/* Just assume "no auth" method supported, for now */
	if (!(MATCH(payload, 0x05, 0x00, 0x00, 0x00)))
		return false;

	if (len != 2)
		return false;

	return true;
	
}

static inline bool match_socks5(lpi_data_t *data) {
	
	if (match_socks5_req(data->payload[0], data->payload_len[0])) {
		if (match_socks5_resp(data->payload[1], data->payload_len[1]))
			return true;
	}
		
	if (match_socks5_req(data->payload[1], data->payload_len[1])) {
		if (match_socks5_resp(data->payload[0], data->payload_len[0]))
			return true;
	}

	return false;

}

static inline bool match_socks4_req(uint32_t payload, uint32_t len) {

	/* Assuming port 80 for now - will update if we see other ports
	 * used 
	 *
	 * Octets 3 and 4 contain the port number */
	if (!(MATCH(payload, 0x04, 0x01, 0x00, 0x50)))
		return false;

	if (len != 9)
		return false;

	return true;
	
}

static inline bool match_socks4_resp(uint32_t payload, uint32_t len) {

	if (len == 0)
		return true;

	/* Haven't seen any legit responses yet :/ */

	return false;
	
}

static inline bool match_socks4(lpi_data_t *data) {

	if (match_socks4_req(data->payload[0], data->payload_len[0])) {
		if (match_socks4_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_socks4_req(data->payload[1], data->payload_len[1])) {
		if (match_socks4_resp(data->payload[0], data->payload_len[0]))
			return true;
	}

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
        if (match_str_both(data, "\x36\x00\x00\x00", "\x33\x00\x00\x00"))
                return true;
        if (match_str_both(data, "\x36\x00\x00\x00", "\x36\x00\x00\x00"))
                return true;
	if (match_str_either(data, "\x33\x00\x00\x00")) {
		if (data->payload_len[0] == 0 && data->payload_len[1] == 87)
			return true;
		if (data->payload_len[1] == 0 && data->payload_len[0] == 87)
			return true;
	}

	if (match_str_either(data, "\x36\x00\x00\x00")) {
		if (data->payload_len[0] == 0 && data->payload_len[1] == 71)
			return true;
		if (data->payload_len[1] == 0 && data->payload_len[0] == 71)
			return true;
	}

	if (match_str_either(data, "\x29\x00\x00\x00")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}
        return false;
}

static inline bool match_afp(lpi_data_t *data) {

	/* Looking for a DSI header - command 4 is OpenSession */
	if (match_str_both(data, "\x00\x04\x00\x01", "\x01\x04\x00\x01"))
		return true;
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

static inline bool match_zynga(lpi_data_t *data) {

	if (match_str_both(data, "pres", "3 se"))
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


static inline bool match_rejection(lpi_data_t *data) {

	/* This is an odd one - the server allows a TCP handshake to complete,
	 * but responds to any requests with a single 0x02 byte. Not sure
	 * whether this is some kind of honeypot or what.
	 *
	 * We see this behaviour on ports 445, 1433 and 80, if we need 
	 * further checking */

	if (MATCH(data->payload[0], 0x02, 0x00, 0x00, 0x00)) {
		if (data->payload_len[0] == 1)
			return true;
	}

	if (MATCH(data->payload[1], 0x02, 0x00, 0x00, 0x00)) {
		if (data->payload_len[1] == 1)
			return true;
	}


	return false;
}


static inline bool match_msnc_transfer(lpi_data_t *data) {

	/* http://msnpiki.msnfanatic.com/index.php/MSNC:File_Transfer#Direct_connection:_Handshake */

	/* MSNC sends the length as a separate packet before the data. To
	 * confirm MSNC, you have to look at the second packet sent by the
	 * connecting host. It should begin with 'foo'. */

	if (match_str_both(data, "\x30\x00\x00\x00", "\x04\x00\x00\x00")) {
		if (data->payload_len[0] == 4 && data->payload_len[1] == 4)
			return true;
	}
	if (match_str_both(data, "\x10\x00\x00\x00", "\x04\x00\x00\x00")) {
		if (MATCH(data->payload[0], 0x04, 0x00, 0x00, 0x00)) {
			if (data->payload_len[0] == 4)
				return true;
		}
		if (MATCH(data->payload[1], 0x04, 0x00, 0x00, 0x00)) {
			if (data->payload_len[1] == 4)
				return true;
		}
	}

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

static inline bool match_tds_request(uint32_t payload, uint32_t len) {

	uint32_t stated_len = 0;
	
	stated_len = (ntohl(payload) & 0xffff);
	if (stated_len != len)
		return false;

	if (MATCH(payload, 0x12, 0x01, ANY, ANY))
		return true;
	if (MATCH(payload, 0x10, 0x01, ANY, ANY))
		return true;

	return false;

}

static inline bool match_tds_response(uint32_t payload, uint32_t len) {
	
	uint32_t stated_len = 0;

	if (len == 0)
		return true;

	if (!MATCH(payload, 0x04, 0x01, ANY, ANY))
		return false;
	stated_len = (ntohl(payload) & 0xffff);
	if (stated_len != len)
		return false;

	return true;


}

static inline bool match_tds(lpi_data_t *data) {

	if (match_tds_request(data->payload[0], data->payload_len[0])) {
		if (match_tds_response(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_tds_request(data->payload[1], data->payload_len[1])) {
		if (match_tds_response(data->payload[0], data->payload_len[0]))
			return true;
	}
        return false;
}

static inline bool match_svn_greet(uint32_t payload, uint32_t len) {

	if (MATCHSTR(payload, "( su"))
		return true;

	return false;

}

static inline bool match_svn_resp(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	
	if (MATCHSTR(payload, "( 2 "))
		return true;
	return false;
}

static inline bool match_svn(lpi_data_t *data) {

	if (match_svn_greet(data->payload[0], data->payload_len[0])) {
		if (match_svn_resp(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_svn_greet(data->payload[1], data->payload_len[1])) {
		if (match_svn_resp(data->payload[0], data->payload_len[0]))
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

	/* XXX Bittorrent-related stuff is covered in 
	 * match_invalid_bittorrent() */

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
        if (match_str_both(data, "450 ", "CONN"))
                return true;

	/* Trying to send HTTP commands to FTP or SMTP servers */
	if (match_str_both(data, "220 ", "GET "))
		return true;
	if (match_str_both(data, "450 ", "GET "))
		return true;

	/* Trying to send HTTP commands to an SVN server */
	if (match_str_both(data, "( su", "GET "))
		return true;

	/* People running an HTTP server on the MS SQL server port */
	if (match_tds_request(data->payload[0], data->payload_len[0])) {
		if (MATCHSTR(data->payload[1], "HTTP"))
			return true;
	}
	if (match_tds_request(data->payload[1], data->payload_len[1])) {
		if (MATCHSTR(data->payload[0], "HTTP"))
			return true;
	}

	return false;
}

static inline bool match_web_junk(lpi_data_t *data) {

	/* Connections to web servers where the client clearly is not
	 * speaking HTTP.
	 *
	 * XXX Check flows matching this occasionally for new HTTP request
	 * types that we've missed :( 
	 */
	if (data->payload_len[0] == 0 || data->payload_len[1] == 0)
		return false;

	if (!match_http_request(data->payload[0], data->payload_len[0])) {
		if (MATCHSTR(data->payload[1], "HTTP"))
			return true;
	}
	
	if (!match_http_request(data->payload[1], data->payload_len[1])) {
		if (MATCHSTR(data->payload[0], "HTTP"))
			return true;
	}

	return false;
}

static inline bool match_invalid_http(lpi_data_t *data) {

	/* This function is for identifying web servers that are not 
	 * following the HTTP spec properly.
	 *
	 * For flows where the client is not doing HTTP properly, see
	 * match_web_junk().
	 */

	/* HTTP servers that appear to respond with raw HTML */
	if (match_str_either(data, "GET ")) {
		if (match_chars_either(data, '<', 'H', 'T', 'M'))
			return true;
		if (match_chars_either(data, '<', 'h', 't', 'm'))
			return true;
		if (match_chars_either(data, '<', 'h', '1', '>'))
			return true;
		if (match_chars_either(data, '<', 't', 'i', 't'))
			return true;
	}

	return false;
}

static inline bool match_invalid_smtp(lpi_data_t *data) {

	/* SMTP flows that do not conform to the spec properly */

	if (match_str_both(data, "250-", "EHLO"))
		return true;
		
	if (match_str_both(data, "250 ", "HELO"))
		return true;
		
	if (match_str_both(data, "220 ", "MAIL"))
		return true;
		
	return false;

}

static inline bool match_invalid_bittorrent(lpi_data_t *data) {

	/* This function will match anyone doing bittorrent in one
	 * direction and *something else* in the other.
	 *
	 * I've broken it down into several separate conditions, just in case
	 * we want to treat them as separate instances later on */



	/* People trying to do Bittorrent to an actual HTTP server, rather than
	 * someone peering on port 80 */
	if (match_str_either(data, "HTTP") && 
			match_chars_either(data, 0x13, 'B', 'i', 't'))
		return true;
	
	/* People sending GETs to a Bittorrent peer?? */
	if (match_str_either(data, "GET ") && 
			match_chars_either(data, 0x13, 'B', 'i', 't'))
		return true;
	
	/* We also get a bunch of cases where one end is doing bittorrent
	 * and the other end is speaking a protocol that begins with a 4
	 * byte length field. */
	if (match_chars_either(data, 0x13, 'B', 'i', 't')) {
		if (match_payload_length(data->payload[0],data->payload_len[0]))
			return true;
		if (match_payload_length(data->payload[1],data->payload_len[1]))
			return true;
	}


	/* This assumes we've checked for regular bittorrent prior to calling
	 * this function! */
	if (match_chars_either(data, 0x13, 'B', 'i', 't'))
		return true;



        return false;
}


static inline bool match_ea_games(lpi_data_t *data) {

	/* Not sure exactly what game this is, but the server matches the
	 * EA IP range and the default port is 9946 */

	if (match_str_both(data, "&lgr", "&lgr"))
		return true;

	if (match_str_either(data, "&lgr")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	return false;

}


static inline bool match_mms_server(uint32_t payload, uint32_t len) {

	if (len != 272)
		return false;
	if (MATCH(payload, 0x01, 0x00, 0x00, 0x00))
		return true;
	return false;
	
}

static inline bool match_mms_client(uint32_t payload, uint32_t len) {

	if (len != 144)
		return false;
	if (MATCH(payload, 0x01, 0x00, 0x00, ANY))
		return true;
	return false;
	
}

static inline bool match_mms(lpi_data_t *data) {

	/* Microsoft Media Server protocol */

	if (match_mms_server(data->payload[0], data->payload_len[0])) {
		if (match_mms_client(data->payload[1], data->payload_len[1]))
			return true;
	}

	if (match_mms_server(data->payload[1], data->payload_len[1])) {
		if (match_mms_client(data->payload[0], data->payload_len[0]))
			return true;
	}
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

static inline bool match_weblogic_t3(lpi_data_t *data) {

	/* T3 is the protocol used by Weblogic, a Java application server */

	/* sa is the admin username for MSSQL databases */
	if (MATCH(data->payload[1], 0x00, 0x02, 's', 'a')) {
		if (match_payload_length(data->payload[0], 
				data->payload_len[0])) 
			return true;
		if (data->client_port == 7001 || data->server_port == 7001)
			return true;
	}

	if (MATCH(data->payload[0], 0x00, 0x02, 's', 'a')) {
		if (match_payload_length(data->payload[1], 
				data->payload_len[1])) 
			return true;
		if (data->client_port == 7001 || data->server_port == 7001)
			return true;
	}
	
	return false;
}


static inline bool match_mystery_9000_payload(uint32_t payload, uint32_t len) {
	if (len == 0)
		return true;
	if (len != 80)
		return false;
	if (MATCH(payload, 0x4c, 0x00, 0x00, 0x00))
		return true;
	return false;
}

static inline bool match_mystery_9000(lpi_data_t *data) {

	/* Not entirely sure what this is - looks kinda like Samba that is
	 * occurring primarily on port 9000. Many storage solutions use
	 * port 9000 as a default port so this is a possibility, but the
	 * use of this protocol is rather spammy */
	
	if (!match_mystery_9000_payload(data->payload[0], data->payload_len[0]))
		return false;
	if (!match_mystery_9000_payload(data->payload[1], data->payload_len[1]))
		return false;

	return true;
}

static inline bool match_mystery_pspr(lpi_data_t *data) {

	if (match_str_both(data, "PSPr", "PSPr"))
		return true;
	if (match_str_either(data, "PSPr")) {
		if (data->payload_len[0] == 0)
			return true;
		if (data->payload_len[1] == 0)
			return true;
	}

	return false;
}

static inline bool match_mystery_iG(lpi_data_t *data) {

	/* Another mystery protocol - the payload pattern is the same in
	 * both directions. Have observed this on port 20005 and port 8080,
	 * but not obvious what exactly this is */

	if (match_str_both(data, "\xd7\x69\x47\x26", "\xd7\x69\x47\x26"))
		return true;
	if (MATCH(data->payload[0], 0xd7, 0x69, 0x47, 0x26)) {
		if (data->payload_len[1] == 0)
			return true;
	}
	if (MATCH(data->payload[1], 0xd7, 0x69, 0x47, 0x26)) {
		if (data->payload_len[0] == 0)
			return true;
	}

	return false;
}

static inline bool match_mystery_conn(lpi_data_t *data) {

	/* Appears to be some sort of file transfer protocol, but
	 * trying to google for a protocol using words such as "connect"
	 * and "receive" is not very helpful */

	if (match_str_both(data, "conn", "reci"))
		return true;

	if (match_str_either(data, "reci")) {
		if (data->payload_len[1] == 0)
			return true;
		if (data->payload_len[0] == 0)
			return true;
	}

	return false;

}

lpi_protocol_t guess_tcp_protocol(lpi_data_t *proto_d)
{
        

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

	if (match_zynga(proto_d)) return LPI_PROTO_ZYNGA;

	if (match_pdbox(proto_d)) return LPI_PROTO_PDBOX;

	if (match_clubbox(proto_d)) return LPI_PROTO_CLUBBOX;

	if (match_winmx(proto_d)) return LPI_PROTO_WINMX;

	if (match_ea_games(proto_d)) return LPI_PROTO_EA_GAMES;
	
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

	if (match_weblogic_t3(proto_d)) return LPI_PROTO_WEBLOGIC;

	if (match_cod_waw(proto_d)) return LPI_PROTO_COD_WAW;

	if (match_mp2p(proto_d)) return LPI_PROTO_MP2P;

	if (match_svn(proto_d)) return LPI_PROTO_SVN;

	if (match_socks4(proto_d)) return LPI_PROTO_SOCKS4;

	if (match_socks5(proto_d)) return LPI_PROTO_SOCKS5;

	if (match_mms(proto_d)) return LPI_PROTO_MMS;

        /* eMule */
        if (match_emule(proto_d)) return LPI_PROTO_EMULE;

        /* Check for any weird broken behaviour, i.e. trying to tunnel via
         * the wrong server */
        if (match_invalid(proto_d)) return LPI_PROTO_INVALID;

	if (match_invalid_http(proto_d)) return LPI_PROTO_INVALID_HTTP;

	if (match_invalid_smtp(proto_d)) return LPI_PROTO_INVALID_SMTP;

	if (match_invalid_bittorrent(proto_d)) return LPI_PROTO_INVALID_BT;

	if (match_web_junk(proto_d)) return LPI_PROTO_WEB_JUNK;

	if (match_mystery_9000(proto_d)) return LPI_PROTO_MYSTERY_9000;

	if (match_mystery_pspr(proto_d)) return LPI_PROTO_MYSTERY_PSPR;

	if (match_mystery_8000(proto_d)) return LPI_PROTO_MYSTERY_8000;

	if (match_mystery_iG(proto_d)) return LPI_PROTO_MYSTERY_IG;

	if (match_mystery_conn(proto_d)) return LPI_PROTO_MYSTERY_CONN;

	/* Leave this one til last */
	if (match_rejection(proto_d)) return LPI_PROTO_REJECTION;

        return LPI_PROTO_UNKNOWN;
}

