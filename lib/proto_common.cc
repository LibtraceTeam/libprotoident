/* 
 * This file is part of libprotoident
 *
 * Copyright (c) 2011-2015 The University of Waikato, Hamilton, New Zealand.
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

#include <string.h>
#include "libprotoident.h"
#include "proto_common.h"

bool match_str_either(lpi_data_t *data, const char *string) {

        if (MATCHSTR(data->payload[0], string))
                return true;
        if (MATCHSTR(data->payload[1], string))
                return true;
        return false;
}

bool match_str_both(lpi_data_t *data, const char *string1,
        const char *string2) {

        if (MATCHSTR(data->payload[0], string1) &&
                MATCHSTR(data->payload[1], string2))
                return true;
        if (MATCHSTR(data->payload[1], string1) &&
                MATCHSTR(data->payload[0], string2))
                return true;
        return false;
}

bool match_chars_either(lpi_data_t *data, char a, char b, char c,
        char d) {

        if (MATCH(data->payload[0], a, b, c, d))
                return true;
        if (MATCH(data->payload[1], a, b, c, d))
                return true;
        return false;
}

bool match_payload_length(uint32_t payload, uint32_t payload_len) {

        uint32_t header = 0;

        header = ntohl(payload);

        /* See if the length in the (presumed) header matches the
         * length of the rest of the packet minus the header itself (4 bytes).
         *
         * Watch out for the case of a 4 byte packet containing just 
         * 00 00 00 00! */
        if (payload_len > 4 && header == payload_len - 4)
                return true;

        return false;
}

bool match_ip_address_both(lpi_data_t *data) {

	uint8_t matches = 0;

	if (data->ips[0] == 0 || data->ips[0] == 0)
		return false;
	
	if (data->payload_len[0] == 0)
		matches += 1;
	else if (data->payload[0] == data->ips[0])
		matches += 1;
	else if (data->payload[0] == data->ips[1])
		matches += 1;
		
	if (data->payload_len[1] == 0)
		matches += 1;
	else if (data->payload[1] == data->ips[0])
		matches += 1;
	else if (data->payload[1] == data->ips[1])
		matches += 1;
	 
	if (matches == 2)
		return true;
	else
		return false;
	
}

/* Multiple protocols use HTTP-style requests */
bool match_http_request(uint32_t payload, uint32_t len) {

        /* HTTP requests - some of these are MS-specific extensions */
        if (len == 0)
                return true;

        if (MATCHSTR(payload, "GET ")) return true;
        if (len == 1 && MATCH(payload, 'G', 0x00, 0x00, 0x00))
                return true;
        if (len == 2 && MATCH(payload, 'G', 'E', 0x00, 0x00))
                return true;
        if (len == 3 && MATCH(payload, 'G', 'E', 'T', 0x00))
                return true;

        if (MATCHSTR(payload, "POST")) return true;
        if (MATCHSTR(payload, "HEAD")) return true;
        if (MATCHSTR(payload, "PUT ")) return true;
        if (MATCHSTR(payload, "DELE")) return true;
        if (MATCHSTR(payload, "auth")) return true;

        /* SVN? */
        if (MATCHSTR(payload, "REPO")) return true;

        /* Webdav */
        if (MATCHSTR(payload, "LOCK")) return true;
        if (MATCHSTR(payload, "UNLO")) return true;
        if (MATCHSTR(payload, "OPTI")) return true;
        if (MATCHSTR(payload, "PROP")) return true;
        if (MATCHSTR(payload, "MKCO")) return true;
        if (MATCHSTR(payload, "POLL")) return true;
        if (MATCHSTR(payload, "SEAR")) return true;

        /* Ntrip - some differential GPS system using modified HTTP */
        if (MATCHSTR(payload, "SOUR")) return true;


        return false;

}

/* File headers are not specific to any particular protocol */
bool match_file_header(uint32_t payload) {

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

        /* GIF */
        if (MATCHSTR(payload, "GIF8"))
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
        if (MATCH(payload, 0x0a, '<', '!', 'D'))
                return true;

        /* 7zip */
        if (MATCH(payload, 0x37, 0x7a, 0xbc, 0xaf))
                return true;

        /* gzip  - may need to replace last two bytes with ANY */
        if (MATCH(payload, 0x1f, 0x8b, 0x08, ANY))
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
	if (MATCHSTR(payload, "\xff\xfb\x90\xc0"))
		return true;

        /* RPM */
        if (MATCH(payload, 0xed, 0xab, 0xee, 0xdb))
                return true;

        /* Wz Patch */
        if (MATCHSTR(payload, "WzPa"))
                return true;

        /* Flash Video */
        if (MATCH(payload, 'F', 'L', 'V', 0x01))
                return true;

        /* .BKF (Microsoft Tape Format) */
        if (MATCHSTR(payload, "TAPE"))
                return true;

        /* MS Office Doc file - this is unpleasantly geeky */
        if (MATCH(payload, 0xd0, 0xcf, 0x11, 0xe0))
                return true;

        /* ASP */
        if (MATCH(payload, 0x3c, 0x25, 0x40, 0x20))
                return true;

        /* WMS file */
        if (MATCH(payload, 0x3c, 0x21, 0x2d, 0x2d))
                return true;

	/* ar archive, typically .deb files */
	if (MATCHSTR(payload, "!<ar"))
		return true;

	/* Raw XML */
	if (MATCHSTR(payload, "<?xm"))
		return true;
	if (MATCHSTR(payload, "<iq "))
		return true;

	/* SPF */
	if (MATCHSTR(payload, "SPFI"))
		return true;

	/* ABIF - Applied Biosystems */
	if (MATCHSTR(payload, "ABIF"))
		return true;

	/* bzip2 - other digits are also possible instead of 9 */
	if (MATCH(payload, 'B', 'Z', 'h', '9'))
		return true;

        /* xz compression format */
        if (MATCH(payload, 0xfd, '7', 'z', 'X'))
                return true;

        /* I'm pretty sure the following are files of some type or another.
         * They crop up pretty often in our test data sets, so I'm going to
         * put them in here.
         *
         * Hopefully one day we will find out what they really are */

        if (MATCH(payload, '<', 'c', 'f', ANY))
                return true;
        if (MATCH(payload, '<', 'C', 'F', ANY))
                return true;
        if (MATCHSTR(payload, ".tem"))
                return true;
        if (MATCHSTR(payload, ".ite"))
                return true;
        if (MATCHSTR(payload, ".lef"))
                return true;

        return false;

}

bool valid_http_port(lpi_data_t *data) {
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
        if (MATCH(payload, 0x16, 0x03, 0x02, ANY))
                return true;
        if (MATCH(payload, 0x16, 0x03, 0x03, ANY))
                return true;
        return false;
}

/* SSLv2 handshake - the ANY byte in the 0x80 payload is actually the length 
 * of the payload - 2. 
 *
 * XXX This isn't always true - consecutive packets may be merged it seems :(
 */
static inline bool match_ssl2_handshake(uint32_t payload, uint32_t len) {
        uint32_t stated_len = 0;

        if (MATCH(payload, 0x80, ANY, 0x01, 0x03))
                return true;
        if (MATCH(payload, 0x81, ANY, 0x01, 0x03))
                return true;

        return false;
}

static inline bool match_tls_alert(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x15, 0x03, 0x01, ANY))
                return true;
        if (MATCH(payload, 0x15, 0x03, 0x02, ANY))
                return true;
        if (MATCH(payload, 0x15, 0x03, 0x03, ANY))
                return true;

	/* Alerts are also possible under SSL 3.0 */
        if (MATCH(payload, 0x15, 0x03, 0x00, ANY))
                return true;
        return false;
}

static inline bool match_tls_change(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x14, 0x03, 0x01, ANY))
                return true;
        if (MATCH(payload, 0x14, 0x03, 0x02, ANY))
                return true;
        if (MATCH(payload, 0x14, 0x03, 0x03, ANY))
                return true;
        return false;

}

static inline bool match_tls_content(uint32_t payload, uint32_t len) {
        if (MATCH(payload, 0x17, 0x03, 0x01, ANY))
                return true;
        if (MATCH(payload, 0x17, 0x03, 0x02, ANY))
                return true;
        if (MATCH(payload, 0x17, 0x03, 0x03, ANY))
                return true;
        return false;
}

bool match_ssl(lpi_data_t *data) {


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
        /* Need to check for TLS alerts (errors) too */
        if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
                        match_tls_alert(data->payload[1], data->payload_len[1]))
                return true;
        if (match_tls_handshake(data->payload[1], data->payload_len[1]) &&
                        match_tls_alert(data->payload[0], data->payload_len[0]))
                return true;

        /* Need to check for cipher changes too */
        if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
                        match_tls_change(data->payload[1], data->payload_len[1]))
                return true;
        if (match_tls_handshake(data->payload[1], data->payload_len[1]) &&
                        match_tls_change(data->payload[0], data->payload_len[0]))
                return true;


        /* Some HTTPS servers respond with unencrypted content, presumably
         * when somebody invalid attempts a connection */
        if (match_tls_handshake(data->payload[0], data->payload_len[0]) &&
                        MATCHSTR(data->payload[1], "<!DO") &&
			data->payload_len[0] != 0)
                return true;
        if (match_tls_handshake(data->payload[1], data->payload_len[1]) &&
                        MATCHSTR(data->payload[0], "<!DO") &&
			data->payload_len[1] != 0)
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

static bool dns_req(uint32_t payload) {

        /* The flags / rcode on requests are usually all zero.
         *
         * Exceptions: CD and RD may be set 
         *
         * Remember BYTE ORDER!
         */

	payload = htonl(payload);

	if ((payload & 0x0000ffff) == 0x00000000)
		return true;
	/* Check for CD */
	if ((payload & 0x0000ffff) == 0x00000010)
		return true;
	/* Check for RD */
	if ((payload & 0x0000ffff) == 0x00000100)
		return true;


        return false;

}

static bool dns_backscatter(uint32_t payload) {

	/* Let's see if we can identify unsolicited DNS responses */

	/* Last byte seems to be always 0x00 - third is either 0x84 or 0x85 */

	payload = htonl(payload);

	if ((payload & 0x0000ffff) == 0x00008500)
		return true;
	if ((payload & 0x0000ffff) == 0x00008580)
		return true;
	if ((payload & 0x0000ffff) == 0x00008400)
		return true;
	if ((payload & 0x0000ffff) == 0x00008480)
		return true;
	if ((payload & 0x0000ffff) == 0x00008483)
		return true;
	if ((payload & 0x0000ffff) == 0x00008403)
		return true;
	if ((payload & 0x0000ffff) == 0x00008000)
		return true;

	return false;
}

bool match_dns(lpi_data_t *data) {

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
                if (data->payload_len[0] > 12 && 
				dns_backscatter(data->payload[0]))
                        return true;
                if (data->payload_len[1] > 12 && 
				dns_backscatter(data->payload[1]))
                        return true;

                return false;
        }

        if (((htonl(data->payload[0])) & 0xffff7800) != 
			((htonl(data->payload[1])) & 0xffff7800))
                return false;

        if ((htonl(data->payload[0]) & 0x00008000) == 
		(htonl(data->payload[1]) & 0x00008000))
                return false;

        return true;

}

bool match_tds_request(uint32_t payload, uint32_t len) {

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


bool match_8000_payload(uint32_t payload, uint32_t len) {

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

bool match_emule(lpi_data_t *data) {

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

static inline bool match_kaspersky_ke(uint32_t payload, uint32_t len) {
        if (len == 0)
                return true;
        if (MATCH(payload, 'K', 'E', 0x00, 0x00))
                return true;
        return false;
}

bool match_kaspersky(lpi_data_t *data) {

	/* Traffic is either on TCP port 443 or UDP port 2001.
	 *
	 * One of the endpoints is always in either a Kaspersky range or
	 * an old PSInet range */

	if (match_str_both(data, "KS\x00\x00", "KS\x00\x00"))
		return true;
	if (match_str_both(data, "PI\x00\x00", "PI\x00\x00")) {
		if (data->payload_len[0] == 2 && data->payload_len[1] == 2)
			return true;
	}
        if (match_kaspersky_ke(data->payload[0], data->payload_len[0])) {
                if (match_kaspersky_ke(data->payload[1], data->payload_len[1]))
                        return true;
        }
	return false;
}

bool match_youku_payload(uint32_t pload, uint32_t len) {

	if (len == 0)
                return true;
        if (MATCH(pload, 0x4b, 0x55, 0x00, 0x01) && len == 16)
                return true;
        if (MATCH(pload, 0x4b, 0x55, 0x00, 0x02))
                return true;
        if (MATCH(pload, 0x4b, 0x55, 0x00, 0x03))
                return true;
        if (MATCH(pload, 0x4b, 0x55, 0x00, 0x04))
                return true;
        return false;

}

bool match_tpkt(uint32_t payload, uint32_t len) {
        uint32_t stated_len = 0;

        /*
         * TPKT header is 03 00 + 2 bytes of length (including the TPKT header)
         */

        if (!MATCH(payload, 0x03, 0x00, ANY, ANY))
                return false;

        stated_len = ntohl(payload) & 0xffff;
        if (stated_len != len)
                return false;
        return true;
}

bool match_qqlive_payload(uint32_t payload, uint32_t len) {

        uint8_t *ptr;
        uint32_t swap;

        /* This appears to have a 3 byte header. First byte is always 0xfe.
         * Second and third bytes are the length (minus the 3 byte header).
         */

        if (len == 0)
                return true;

        swap = htonl(payload);
        swap = (swap & 0xffff00) >> 8;

        if (ntohs(swap) != len - 3)
                return false;

	/* Interestingly, the third and fourth byte always match */
        swap = htonl(payload);
        if ((swap & 0xff) != ((swap & 0xff00) >> 8))
                return false;

        if (MATCH(payload, 0xfe, ANY, ANY, ANY))
                return true;
        return false;

}

