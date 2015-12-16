%define default_release 10

Name: accre-ibp-server
Version: 1.0
Release: %{?release}%{!?release:%{default_release}}
Summary: Internet Backplane Protocol (IBP) Server

Group: Applications/System
License: ACCRE
URL: http://www.reddnet.org/
Source0: ibp_server.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires: cmake apr-devel apr-util-devel openssl-devel gcc gcc-c++ openssl-devel jansson-devel leveldb-devel snappy-devel rpmconf
Requires: czmq fuse openssl jansson libunis-c python-argparse leveldb snappy rpmconf

%description
The Internet Backplane Protocol (IBP) Server handles exposes storage 
to the network via IBP. It is an integral part of various distributed
storage technologies (ex http://www.reddnet.org). In case of bug or issue 
please report it to data-logistics@googlegroups.org.

%prep
%setup -n ibp_server

%build
./bootstrap
cmake -DCMAKE_INSTALL_PREFIX:PATH=%{buildroot} .
make

%install
chmod 755 misc/ibp-server
make install 
install -d ${RPM_BUILD_ROOT}/usr/bin
install -d ${RPM_BUILD_ROOT}/etc/ibp
install -m 755 ibp_server ibp_attach_rid ibp_detach_rid ibp_rescan ${RPM_BUILD_ROOT}/usr/bin
install -m 755 get_alloc get_config get_corrupt get_version ${RPM_BUILD_ROOT}/usr/bin
install -m 755 print_alog read_alloc repair_history ${RPM_BUILD_ROOT}/usr/bin
install -m 755 date_spacefree chksum_test expire_list mkfs.resource ${RPM_BUILD_ROOT}/usr/bin
install -m 755 misc/ibp_configure.py ${RPM_BUILD_ROOT}/usr/bin
install -m 644 misc/dlt-client.pem ${RPM_BUILD_ROOT}/etc/ibp
install -m 644 misc/dlt-client.key ${RPM_BUILD_ROOT}/etc/ibp
install -m 644 misc/dlt-ca.bundle ${RPM_BUILD_ROOT}/etc/ibp
rm -rf ${RPM_BUILD_ROOT}/bin

%clean
rm -rf %{buildroot}

%pre
/usr/bin/getent group ibp || /usr/sbin/groupadd -r ibp
/usr/bin/getent passwd ibp || /usr/sbin/useradd -r -d /etc/ibp -s /sbin/nologin -g ibp ibp

%postun

%post
rpmconf --owner=accre-ibp-server

%files
%defattr(-,root,root,-)
/usr/bin/*
%config(noreplace) /etc/ibp/ibp.cfg
/etc/ibp/dlt-client.pem
/etc/ibp/dlt-client.key
/etc/ibp/dlt-ca.bundle
%attr(755,root,root) /etc/init.d/ibp-server

%changelog
* Tue Dec 08 2015 <ezkissel@indiana.edu> 1.0-10-accre-ibp-server
- Added support to run ibp_server as a non-root user, specified in config.
* Tue Nov 03 2015 <jayaajay@indiana.edu> 1.0-9-accre-ibp-server
- Updated the paths to executables and sysconf files.
* Thu Oct 08 2015 <exkissel@indiana.edu> 1.0-8-accre-ibp-server
- Include DLT CA file for SSL server verification.
* Thu Oct 16 2014 <ezkissel@indiana.edu> 1.0-6-accre-ibp-server 
- Minor configure script improvements.  Default RID is now 1.  Prompt to delete existing DB env.
* Sat Oct 11 2014 <ezkissel@indiana.edu> 1.0-5-accre-ibp-server 
- Updates to ibp_configure.py.  Including DLT client certificate for UNIS registration.
* Thu May 30 2014 Akshay Dorwat <adorwat@indiana.edu> 1.0-4-accre-ibp-server 
- Updated the ibp_configure.py to suppress DEBUG warning and added note to add more resources in IBP_SERVER.
* Thu May 29 2014 Akshay Dorwat <adorwat@indiana.edu> 1.0-2-accre-ibp-server 
- Fixed the bug in ibp_configure.py script. 
* Tue May 27 2014 Akshay Dorwat <adorwat@indiana.edu> 1.0-1-accre-ibp-server 
- Updated the permissions for /etc/init.d/ibp-server script.
