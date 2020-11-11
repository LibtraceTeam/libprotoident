Name:           libprotoident
Version:        2.0.15
Release:        1%{?dist}
Summary:        C/C++ Library for performing lightweight traffic classification

License:        LGPLv3
URL:            https://github.com/wanduow/libprotoident
Source0:        https://github.com/wanduow/libprotoident/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: libtrace4-devel
BuildRequires: libflowmanager-devel

Provides: libprotoident

%description
libprotoident is a library that can perform traffic classification
on each network flow observed via a packet capture process (including
pcap trace files and many common live packet capture approaches).
The classification is performed by examining the packet headers and
first four bytes of application payload only, so can be used in
environments where full payload capture is not possible.

libprotoident is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%package        tools
Summary:        Example software utilities for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description tools
The %{name}-tools package contains example utilities that make use of the
%{name} library.

%prep
%setup -q -n libprotoident-%{version}

%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%{_libdir}/libprotoident.so.*

%files devel
%{_includedir}/libprotoident*
%{_libdir}/libprotoident.so
%{_libdir}/libprotoident.a

%files tools
%{_bindir}/*
%{_mandir}/man1/*

%changelog
* Thu Nov 12 2020 Shane Alcock <shane.alcock@waikato.ac.nz> - 2.0.15-1
- First libprotoident RPM package
