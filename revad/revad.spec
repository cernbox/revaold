# 
# revad spec file
#

Name: revad
Summary: REVA is a gRPC backend server for CERNBox
Version: 0.0.43
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides REVA, a gRPC server that enables sync and share in CERNBox.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/revad
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/revad
install -m 755 revad	     %buildroot/usr/local/bin/revad
install -m 644 revad.service    %buildroot/usr/lib/systemd/system/revad.service
install -m 644 revad.yaml       %buildroot/etc/revad/revad.yaml
install -m 644 revad.logrotate  %buildroot/etc/logrotate.d/revad

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/revad
/etc/logrotate.d/revad
/var/log/revad
/usr/lib/systemd/system/revad.service
/usr/local/bin/*
%config(noreplace) /etc/revad/revad.yaml

%changelog
* Mon Nov 11 2019 Diogo Castro <diogo.castro@cern.ch> 0.0.43
- Fix home folder creation script for new homes
* Wed Oct 23 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.42
- Fix restoring from EOS recycle
* Thu Aug 22 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.41
- Fix download of file versions
* Thu Jun 20 2019 Diogo Castro <diogo.castro@cern.ch> 0.0.40
- gantt mimetype
* Tue May 21 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.39
- Allow listing recycle entries by date range
* Fri Mar 22 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.38
- Print mgm url in eosclient logs
* Fri Mar 22 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.37
- Fix migration logic for projects
* Thu Mar 21 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.36
- Support project space migration
* Mon Feb 18 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.35
- Add restart=always to systemd
* Thu Dec 13 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.34
- Add vsd mimetype
* Fri Nov 30 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.33
- Add ctime, uid and gid to eosclient
- Check if link is read only before giving access using storage_public_link
* Tue Nov 27 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.32
- Add revision support for storage_all_projects
* Tue Nov 20 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.31
- Use "eos acl" cmd for acl manipulation on citrine servers
* Mon Nov 19 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.30
- Add drop-only support for public links
* Tue Nov 12 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.29
- Limit recycle ls output to current day
* Fri Nov 9 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.28
- Add force_read_only flag to eos storages
* Fri Nov 2 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.27
- Fix filtering by path when mount is not using migration ids.
* Thu Oct 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.26
- Fix filtering by path when pointing to files
* Thu Oct 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.25
- Add support for filtering shares by path and disable share cache
* Thu Oct 18 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.24
- Fix handling of colon prefixes in the mounts
* Thu Oct 11 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.23
- Use oc_share_acl to reject shares
* Thu Oct 10 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.22
- Add decline share functionality
* Tue Oct 09 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.21
- Support application/x-drawio mimetype
* Tue Oct 09 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.20
- Add display_name attrbute to user token
* Wed Sep 26 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.19
- Fix parsing of eos file info
* Tue Aug 28 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.18
* Fri Aug 17 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.17
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.16
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.15
- Fix fd leak #11
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.14
* Mon Aug 13 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.13
- Add LDAP auth manager driver
* Tue Aug 07 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.12
* Tue Aug 07 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.11
* Tue Aug 07 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.10
* Mon Aug 06 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.9
* Sun Aug 05 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.8
* Thu Aug 03 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.7
* Thu Aug 02 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.6
- Improve mime type support
* Thu Aug 02 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.5
* Wed Aug 01 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.4
- EOS Storage: hide .sys. files from recycle ls
- Mount: fix logic when checking if sharing is enabled
* Tue Jul 31 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.3
- Respect read-only and shareability conf of inner mounts for mig mounts
* Tue Jul 31 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.2
- Sharing, Favourites and Project space support
* Tue Jul 03 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.1
- First version
