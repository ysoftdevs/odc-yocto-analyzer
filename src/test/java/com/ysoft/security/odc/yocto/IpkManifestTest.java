package com.ysoft.security.odc.yocto;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import static org.junit.Assert.*;

public class IpkManifestTest {

    @Test
    public void testCveParseXinetd(){
        final IpkManifest ipkManifest = new IpkManifest(ImmutableMap.of(new Key("Source"), "git://github.com/xinetd-org/xinetd.git;protocol=https "
                + "file://xinetd.init file://xinetd.conf file://xinetd.default file://Various-fixes-from-the-previous-maintainer.patch "
                + "file://Disable-services-from-inetd.conf-if-a-service-with-t.patch file://xinetd-should-be-able-to-listen-on-IPv6-even-in-ine.patch "
                + "file://xinetd-CVE-2013-4342.patch file://xinetd.service"));
        assertEquals(ImmutableSet.of("CVE-2013-4342"), ipkManifest.getFixedCves());
    }

    @Test
    public void testCveParseOpenSsh(){
        final IpkManifest ipkManifest = new IpkManifest(ImmutableMap.of(new Key("Source"), "Source: ftp://ftp.openbsd"
                + ".org/pub/OpenBSD/OpenSSH/portable/openssh-7.1p2.tar.gz file://sshd_config file://ssh_config file://init file://sshd file://sshd"
                + ".socket file://sshd@.service file://sshdgenkeys.service file://volatiles.99_sshd file://add-test-support-for-busybox.patch "
                + "file://run-ptest file://CVE-2016-1907_upstream_commit.patch file://CVE-2016-1907_2.patch file://CVE-2016-1907_3.patch "
                + "file://CVE-2016-3115.patch file://sshdgenkeys.service\n"
                + "/home/user/projects/odc-yocto-analyzer/sample/cortexa9t2hf-vfp-neon/openssh-ssh_7.1p2-r0_cortexa9t2hf-vfp-neon.ipk"));
        assertEquals(ImmutableSet.of("CVE-2016-1907", "CVE-2016-1907", "CVE-2016-1907", "CVE-2016-3115"), ipkManifest.getFixedCves());
    }

    @Test
    public void testCveParseLibXml2(){
        final IpkManifest ipkManifest = new IpkManifest(ImmutableMap.of(new Key("Source"), "Source: ftp://xmlsoft.org/libxml2/libxml2-2.9.2.tar.gz;"
                + "name=libtar file://libxml-64bit.patch file://ansidecl.patch file://runtest.patch file://run-ptest file://libxml2-CVE-2014-0191-fix"
                + ".patch file://python-sitepackages-dir.patch file://libxml-m4-use-pkgconfig.patch file://configure.ac-fix-cross-compiling-warning"
                + ".patch file://0001-CVE-2015-1819-Enforce-the-reader-to-run-in-constant-.patch "
                + "file://CVE-2015-7941-1-Stop-parsing-on-entities-boundaries-errors.patch "
                + "file://CVE-2015-7941-2-Cleanup-conditional-section-error-handling.patch "
                + "file://CVE-2015-8317-Fail-parsing-early-on-if-encoding-conversion-failed.patch "
                + "file://CVE-2015-7942-Another-variation-of-overflow-in-Conditional-section.patch "
                + "file://CVE-2015-7942-2-Fix-an-error-in-previous-Conditional-section-patch.patch "
                + "file://0001-CVE-2015-8035-Fix-XZ-compression-support-loop.patch "
                + "file://CVE-2015-7498-Avoid-processing-entities-after-encoding-conversion-.patch "
                + "file://0001-CVE-2015-7497-Avoid-an-heap-buffer-overflow-in-xmlDi.patch file://CVE-2015-7499-1-Add-xmlHaltParser-to-stop-the-parser"
                + ".patch file://CVE-2015-7499-2-Detect-incoherency-on-GROW.patch file://0001-Fix-a-bug-on-name-parsing-at-the-end-of-current-inpu"
                + ".patch file://0001-CVE-2015-7500-Fix-memory-access-error-due-to-incorre.patch "
                + "file://0001-CVE-2015-8242-Buffer-overead-with-HTML-parser-in-pus.patch file://0001-CVE-2015-5312-Another-entity-expansion-issue"
                + ".patch file://CVE-2015-8241.patch file://CVE-2015-8710.patch http://www.w3.org/XML/Test/xmlts20080827.tar.gz;name=testtar "
                + "file://72a46a519ce7326d9a00f0b6a7f2a8e958cd1675.patch file://0001-threads-Define-pthread-definitions-for-glibc-complia.patch"));
        assertEquals(ImmutableSet.of("CVE-2014-0191", "CVE-2015-1819", "CVE-2015-7941", "CVE-2015-8317", "CVE-2015-7942", "CVE-2015-8035",
                "CVE-2015-7498", "CVE-2015-7497", "CVE-2015-7499", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-8242", "CVE-2015-5312",
                "CVE-2015-8241", "CVE-2015-8710"), ipkManifest.getFixedCves());
    }

}