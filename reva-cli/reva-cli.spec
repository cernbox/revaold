# 
# reva-cli spec file
#

Name: reva-cli
Summary: reva-cli is the cli tool to interact with the reva-cli daemon.
Version: 0.0.1
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides reva-cli, a cli tool to interact with the reva-cli daemon.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
install -m 755 reva-cli	     %buildroot/usr/local/bin/reva-cli

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/usr/local/bin/*

%changelog
* Thu Aug 15 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.1
- First version
