# 
# revad spec file
#

Name: revad
Summary: REVA gRCP server
Version: 0.0.1
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
* Tue Jul 03 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.1
