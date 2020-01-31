package com.ysoft.security.odc.yocto;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class IpkFile {

    private final IpkManifest manifest;
    //private final Set<String> fileNames;

    public IpkFile(IpkManifest manifest/*, Set<String> fileNames*/) {
        this.manifest = manifest;
        //this.fileNames = fileNames;
    }

    public IpkManifest getManifest() {
        return manifest;
    }

    /*public Set<String> getFileNames() {
        return fileNames;
    }*/

    public Set<String> getFixedCves() {
        return manifest.getFixedCves();
    }

    public String getPackageName(){
        return manifest.get(IpkManifest.KEY_PACKAGE);
    }

    public String getVersion(){
        return manifest.get(IpkManifest.KEY_VERSION);
    }

    public String getDescription(){
        return manifest.get(IpkManifest.KEY_DESCRIPTION);
    }

    public String getLicense(){
        return manifest.get(IpkManifest.KEY_LICENSE);
    }

    public String getHomepage(){
        return manifest.get(IpkManifest.KEY_HOMEPAGE);
    }

    public String getOE(){
        return manifest.get(IpkManifest.KEY_OE);
    }

    public List<String> getSources(boolean experimentalDebEnabled){
        final String source = experimentalDebEnabled
                ? manifest.get(IpkManifest.KEY_SOURCE, "")
                : manifest.get(IpkManifest.KEY_SOURCE);
        return Arrays.asList(source.split("\\s+"));
    }

    @Override
    public String toString() {
        return "IpkFile{" +
                "manifest=" + manifest +
                //", fileNames=" + fileNames +
                '}';
    }
}
