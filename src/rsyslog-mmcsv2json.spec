Name:	rsyslog-mmcsv2json	
Version:	0.1.0
Release:	1%{?dist}
Summary:	csv to json modification for rsyslog

Group:		System Environment/Daemons
License:	(GPLv3+ and ASL 2.0)
URL:		https://github.com/guoxiaod/rsyslog-mmcsv2json.git
Source0:	%{name}-%{version}.tgz

BuildRequires: libfastjson4-devel, libcsv-devel, libestr-devel, libuuid-devel
BuildRequires: libgcrypt-devel, liblogging-devel
Requires:	libfastjson4, libcsv, libestr, libuuid, libgcrypt, liblogging

%description
Rsyslog csv to json modification

%prep
%setup -q


%build
cd rsyslog/ 
%configure
cd -
make %{?_smp_mflags}


%install
%make_install


%files
/lib64/rsyslog/


%changelog
