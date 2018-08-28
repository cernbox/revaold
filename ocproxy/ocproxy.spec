# 
# ocproxy spec file
#

Name: ocproxy
Summary: ownCloud Proxy
Version: 0.0.21
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides an ownCloud Proxy for CERNBox REVA daemon.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/ocproxy
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/ocproxy
install -m 755 ocproxy	     %buildroot/usr/local/bin/ocproxy
install -m 644 ocproxy.service    %buildroot/usr/lib/systemd/system/ocproxy.service
install -m 644 ocproxy.yaml       %buildroot/etc/ocproxy/ocproxy.yaml
install -m 644 ocproxy.logrotate  %buildroot/etc/logrotate.d/ocproxy

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/ocproxy
/etc/logrotate.d/ocproxy
/var/log/ocproxy
/usr/lib/systemd/system/ocproxy.service
/usr/local/bin/*
%config(noreplace) /etc/ocproxy/ocproxy.yaml


%changelog
* Tue Aug 28 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.21
* Fri Aug 24 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.20
* Fri Aug 24 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.19
* Wed Aug 21 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.18
* Tue Aug 21 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.17
* Mon Aug 20 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.16
* Fri Aug 17 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.15
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.14
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.13
* Thu Aug 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.12
* Fri Aug 10 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.11
- Fix tar archive creation for windows platfrom
* Tue Aug 07 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.10
- Fix download of public link and mtime info on listing folders
* Mon Aug 06 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.9
* Mon Aug 06 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.8
* Mon Aug 06 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.7
* Sun Aug 05 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.6
* Fri Aug 03 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.5
- Add share cache
* Thu Aug 02 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.4
- Add SWAN support
* Thu Aug 02 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.3
* Tue Jul 31 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.2
- Sharing, Favourites and Project Space support
* Tue Jul 03 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.1
- First version
