#! /bin/sh

set -x
# Prefer aclocal 1.9 if we can find it
aclocal-1.11  || aclocal-1.9 || aclocal 

# Darwin bizarrely uses glibtoolize
libtoolize --force --copy ||
	glibtoolize --force --copy

autoheader2.50 || autoheader

# Prefer automake-1.9 if we can find it
automake-1.11 --add-missing --copy --foreign ||
	automake-1.10 --add-missing --copy --foreign || 
	automake-1.9 --add-missing --copy --foreign || 
	automake --add-missing --copy --foreign

autoconf2.50 || autoconf 
