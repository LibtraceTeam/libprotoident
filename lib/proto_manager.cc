#include "config.h"

#include <glob.h>
#include <dlfcn.h>

#include "proto_manager.h"

int register_protocols(LPIModuleMap *mod_map, char *location) {
	glob_t glob_buf;
	void *hdl;
	const char *error;
	LPIModuleList *ml;
	LPIModuleMap::iterator it;

	lpi_module_t *new_module;
	char full_loc[10000];

	if (location == NULL) {

		fprintf(stderr, "NULL location passed to register_protocols\n");
		return -1;
	}

	if (mod_map == NULL) {
		fprintf(stderr, "NULL module list passed to register_protocols\n");
		return -1;
	}

	strncpy(full_loc, location, 10000-10);
	strncat(full_loc, "/*.so", strlen("/*.so") + 1);
	glob(full_loc, 0, NULL, &glob_buf);

	for (uint32_t i = 0; i < glob_buf.gl_pathc; i++) {
		fprintf(stderr, "Registering %s\n", glob_buf.gl_pathv[i]);

		hdl = dlopen(glob_buf.gl_pathv[i], RTLD_LAZY);

		if (!hdl) {
			fprintf(stderr, "Failed to open shared library\n");
			if ((error = dlerror()) != NULL)
				fprintf(stderr, "%s\n", error);
			continue;
		}

		lpi_reg_ptr r_func = (lpi_reg_ptr)dlsym(hdl, "lpi_register");
		if ((error = dlerror()) != NULL) {
			fprintf(stderr, "Error: %s\n", error);
			continue;
		}

		new_module = r_func();
		if (new_module == NULL) {
			fprintf(stderr, "Failed to register protocol: %s\n",
					glob_buf.gl_pathv[i]);
			continue;
		}

		new_module->dlhandle = hdl;
		
		it = mod_map->find(new_module->priority); 

		if (it == mod_map->end()) {
			(*mod_map)[new_module->priority] = new LPIModuleList();
			
			it = mod_map->find(new_module->priority);
		}
		
		ml = it->second;
		ml->push_back(new_module);


	}

	globfree(&glob_buf);
	return 0;

}

void init_other_protocols() {

	lpi_icmp = new lpi_module_t;

	lpi_icmp->protocol = LPI_PROTO_ICMP;
	lpi_icmp->category = LPI_CATEGORY_ICMP;
	lpi_icmp->dlhandle = NULL;
	strncpy(lpi_icmp->name, "ICMP", 255);
	lpi_icmp->priority = 255;
	lpi_icmp->lpi_callback = NULL;

	lpi_unknown_tcp = new lpi_module_t;

	lpi_unknown_tcp->protocol = LPI_PROTO_UNKNOWN;
	lpi_unknown_tcp->category = LPI_CATEGORY_UNKNOWN;
	lpi_unknown_tcp->dlhandle = NULL;
	strncpy(lpi_unknown_tcp->name, "Unknown_TCP", 255);
	lpi_unknown_tcp->priority = 255;
	lpi_unknown_tcp->lpi_callback = NULL;
	
	lpi_unknown_udp = new lpi_module_t;

	lpi_unknown_udp->protocol = LPI_PROTO_UDP;
	lpi_unknown_udp->category = LPI_CATEGORY_UNKNOWN;
	lpi_unknown_udp->dlhandle = NULL;
	strncpy(lpi_unknown_udp->name, "Unknown_UDP", 255);
	lpi_unknown_udp->priority = 255;
	lpi_unknown_udp->lpi_callback = NULL;

	lpi_unsupported = new lpi_module_t;

	lpi_unsupported->protocol = LPI_PROTO_UNSUPPORTED;
	lpi_unsupported->category = LPI_CATEGORY_UNSUPPORTED;
	lpi_unsupported->dlhandle = NULL;
	strncpy(lpi_unsupported->name, "Unsupported", 255);
	lpi_unsupported->priority = 255;
	lpi_unsupported->lpi_callback = NULL;

}

