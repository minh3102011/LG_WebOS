SUMMARY = "Netfilter userspace logging daemon" 
DESCRIPTION = "Userspace logging daemon for netfilter/iptables related logging" 
HOMEPAGE = "http://www.netfilter.org/projects/ulogd/index.html" 
LICENSE = "GPL-2.0-only" 
LIC_FILES_CHKSUM = "file://COPYING;md5=c93c0550bd3173f4504b2cbd8991e50b" 
DEPENDS = "libnfnetlink libmnl libnetfilter-log libnetfilter-conntrack jansson" 
RDEPENDS_${PN} = "libnfnetlink libmnl libnetfilter-log libnetfilter-conntrack jansson" 
PR = "r2" 
PV = "2.0.7"
S = "${WORKDIR}/${PN}-${PV}" 


SRC_URI = " \ 
 http://www.netfilter.org/projects/ulogd/files/ulogd-${PV}.tar.bz2;name=tar \ 
 file://ulogd.service \ 
 file://ulogd.conf.in.user \ 
 file://ulogd.logrotate.user \ 
 file://ulogd.init \
" 

SRC_URI[tar.md5sum] = "2bb2868cf51acbb90c35763c9f995f31" 
SRC_URI[tar.sha256sum] = "990a05494d9c16029ba0a83f3b7294fc05c756546b8d60d1c1572dc25249a92b"
 
#inherit autotools manpages pkgconfig systemd update-rc.d

EXTRA_OECONF = "\
--disable-nfacct \ 
 --without-dbi \ 
 --without-sqlite \ 
 --without-pgsql \ 
 --without-mysql \ 
 --without-pcap \ 



do_install:append () {
        install -d ${D}${sysconfdir}/ulogd
        install -m 0644 ${WORKDIR}/ulogd.conf.in.user ${D}${sysconfdir}/ulogd.conf
        install -d ${D}${sysconfdir}/logrotate.d
        install -m 0644 ${WORKDIR}/ulogd.logrotate.user ${D}${sysconfdir}/logrotate.d/ulogd.logrotate 
        install -d ${D}${mandir}/man8
        install -m 0644 ${S}/ulogd.8 ${D}${mandir}/man8/ulogd.8

        install -d ${D}${systemd_system_unitdir}
        install -m 0644 ${WORKDIR}/ulogd.service ${D}${systemd_system_unitdir}
        sed -i -e 's,@SBINDIR@,${sbindir},g' ${D}${systemd_system_unitdir}/ulogd.service

        install -d ${D}${sysconfdir}/init.d
        install -m 755 ${WORKDIR}/ulogd.init ${D}${sysconfdir}/init.d/ulogd
}

PACKAGES += "${PN}-plugins"
ALLOW_EMPTY:${PN}-plugins = "1"

PACKAGES_DYNAMIC += "^${PN}-plugin-.*$"
NOAUTOPACKAGEDEBUG = "1"

CONFFILES:${PN} = "${sysconfdir}/ulogd.conf"
RRECOMMENDS:${PN} += "${PN}-plugins"

FILES:${PN}-dbg += "${sbindir}/.debug"

python split_ulogd_libs () {
    libdir = d.expand('${libdir}/ulogd')
    dbglibdir = os.path.join(libdir, '.debug')

    split_packages = do_split_packages(d, libdir, r'^ulogd_.*\_([A-Z0-9]*).so', '${PN}-plugin-%s', 'ulogd2 %s plugin', prepend=True)
    split_dbg_packages = do_split_packages(d, dbglibdir, r'^ulogd_.*\_([A-Z0-9]*).so', '${PN}-plugin-%s-dbg', 'ulogd2 %s plugin - Debugging files', prepend=True, extra_depends='${PN}-dbg')

    if split_packages:
        pn = d.getVar('PN')
        d.setVar('RRECOMMENDS:' + pn + '-plugins', ' '.join(split_packages))
        d.appendVar('RRECOMMENDS:' + pn + '-dbg', ' ' + ' '.join(split_dbg_packages))
}
PACKAGESPLITFUNCS:prepend = "split_ulogd_libs "

SYSTEMD_SERVICE:${PN} = "ulogd.service"

INITSCRIPT_NAME = "ulogd"
INITSCRIPT_PARAMS = "defaults"

