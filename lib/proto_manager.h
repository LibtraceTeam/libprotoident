#ifndef PROTO_MANAGER_H_
#define PROTO_MANAGER_H_

#include <list>
#include <vector>
#include <map>

#include "libprotoident.h"


typedef std::list<lpi_module_t *> LPIModuleList;
typedef std::map<uint8_t, LPIModuleList *> LPIModuleMap;

typedef lpi_module_t *(* lpi_reg_ptr) ();

void register_protocol(lpi_module_t *mod, LPIModuleMap *mod_map);
int register_tcp_protocols(LPIModuleMap *mod_map);
int register_udp_protocols(LPIModuleMap *mod_map);
void init_other_protocols();

//int register_protocols(LPIModuleMap *mod_list, char *location);

extern lpi_module_t *lpi_icmp;
extern lpi_module_t *lpi_unknown_tcp;
extern lpi_module_t *lpi_unknown_udp;
extern lpi_module_t *lpi_unsupported;

#endif
