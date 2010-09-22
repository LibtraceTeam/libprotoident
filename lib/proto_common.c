
#include "libprotoident.h"
#include "proto_common.h"

inline bool match_str_either(lpi_data_t *data, const char *string) {

        if (MATCHSTR(data->payload[0], string))
                return true;
        if (MATCHSTR(data->payload[1], string))
                return true;
        return false;
}

inline bool match_str_both(lpi_data_t *data, const char *string1,
        const char *string2) {

        if (MATCHSTR(data->payload[0], string1) &&
                MATCHSTR(data->payload[1], string2))
                return true;
        if (MATCHSTR(data->payload[1], string1) &&
                MATCHSTR(data->payload[0], string2))
                return true;
        return false;
}

inline bool match_chars_either(lpi_data_t *data, char a, char b, char c,
        char d) {

        if (MATCH(data->payload[0], a, b, c, d))
                return true;
        if (MATCH(data->payload[1], a, b, c, d))
                return true;
        return false;
}

inline bool match_payload_length(uint32_t payload, uint32_t payload_len) {

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

