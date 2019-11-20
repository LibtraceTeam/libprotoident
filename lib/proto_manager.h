/*
 *
 * Copyright (c) 2011-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libprotoident.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


#ifndef PROTO_MANAGER_H_
#define PROTO_MANAGER_H_

#include <list>
#include <vector>
#include <map>
#include <string>

#include "libprotoident.h"

typedef std::list<lpi_module_t *> LPIModuleList;
typedef std::map<uint8_t, LPIModuleList *> LPIModuleMap;
typedef std::map<lpi_protocol_t, const char *> LPINameMap;
typedef std::map<std::string, lpi_protocol_t> LPIProtocolMap;

void register_protocol(lpi_module_t *mod, LPIModuleMap *mod_map);
int register_tcp_protocols(LPIModuleMap *mod_map);
int register_udp_protocols(LPIModuleMap *mod_map);
void register_names(LPIModuleMap *mod_map, LPINameMap *name_map, LPIProtocolMap *proto_map);
void init_other_protocols(LPINameMap *name_map, LPIProtocolMap *proto_map);
void free_protocols(LPIModuleMap *mod_map);


extern lpi_module_t *lpi_icmp;
extern lpi_module_t *lpi_unknown_tcp;
extern lpi_module_t *lpi_unknown_udp;
extern lpi_module_t *lpi_unsupported;

#endif
