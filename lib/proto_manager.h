#ifndef PROTO_MANAGER_H_
#define PROTO_MANAGER_H_

#include <list>
#include <vector>
#include <map>

#include "libprotoident.h"


typedef std::list<lpi_module_t *> LPIModuleList;
typedef std::map<uint8_t, LPIModuleList *> LPIModuleMap;

typedef lpi_module_t *(* lpi_reg_ptr) ();

int register_protocols(LPIModuleMap *mod_list, char *location);
void init_other_protocols();

extern lpi_module_t *lpi_icmp;
extern lpi_module_t *lpi_unknown_tcp;
extern lpi_module_t *lpi_unknown_udp;
extern lpi_module_t *lpi_unsupported;

#endif
