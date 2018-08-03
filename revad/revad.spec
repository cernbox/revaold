# 
# revad spec file
#

Name: revad
Summary: REVA is a gRPC backend server for CERNBox
Version: 0.0.6
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
