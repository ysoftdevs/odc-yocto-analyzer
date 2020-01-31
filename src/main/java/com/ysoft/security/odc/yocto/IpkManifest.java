package com.ysoft.security.odc.yocto;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IpkManifest {

    public static final Key KEY_PACKAGE = new Key("Package");
    public static final Key KEY_VERSION = new Key("Version");
    public static final Key KEY_DESCRIPTION = new Key("Description");
    public static final Key KEY_LICENSE = new Key("License");
    public static final Key KEY_HOMEPAGE = new Key("Homepage");
    public static final Key KEY_SOURCE = new Key("Source");
    public static final Key KEY_OE = new Key("OE");

    private static final Pattern CVE_REGEX = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}"); // slightly more permissible than https://cve.mitre.org/cve/identifiers/syntaxchange.html (leading zeros, number length)
    private final Map<Key, String> manifest;
    
    public IpkManifest(Map<Key, String> manifest) {
        this.manifest = manifest;
    }

    public String get(Key key){
        return manifest.get(key);
    }

    public String get(Key key, String defaultValue){
        return manifest.getOrDefault(key, defaultValue);
    }

    public Set<String> getFixedCves() {
        final Matcher matcher = CVE_REGEX.matcher(manifest.getOrDefault(KEY_SOURCE, ""));
        final Set<String> set = new HashSet<>();
        while(matcher.find()){
            set.add(matcher.group());
        }
        return Collections.unmodifiableSet(set);
    }

    @Override
    public String toString() {
        return "IpkManifest{" +
                "manifest=" + manifest +
                '}';
    }
}
