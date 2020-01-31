package com.ysoft.security.odc.yocto;

import com.github.packageurl.MalformedPackageURLException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;

import java.io.IOException;
import java.util.List;

import static org.owasp.dependencycheck.dependency.EvidenceType.*;

public class YoctoAnalyzer extends AbstractYoctoAnalyzer {

    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {}

    public String getName() {
        return "YOCTO analyzer";
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final IpkFile ipkFile = parseIpkFile(dependency.getActualFile());

            dependency.addSoftwareIdentifier(new PurlIdentifier("yocto", ipkFile.getPackageName(), ipkFile.getVersion(), Confidence.HIGHEST));
            dependency.addEvidence(PRODUCT, IPK_SOURCE, "package name", ipkFile.getPackageName(), Confidence.HIGHEST);
            dependency.addEvidence(VENDOR, IPK_SOURCE, "package name", ipkFile.getPackageName()+"_project", Confidence.LOW);
            final String oe = ipkFile.getOE();
            final List<String> sources = ipkFile.getSources(isExperimentalDebEnabled());
            if(!sources.isEmpty()){
                dependency.addEvidence(VENDOR, IPK_SOURCE, "source url", sources.get(0), Confidence.MEDIUM);
                //productEvidence.addEvidence(IPK_SOURCE, "source url", sources.get(0), Confidence.MEDIUM);
            }
            if(oe != null){
                dependency.addEvidence(PRODUCT, IPK_SOURCE, "name", oe, Confidence.HIGHEST);
                dependency.addEvidence(VENDOR, IPK_SOURCE, "name", oe+"_project", Confidence.LOW);
            }
            dependency.addEvidence(VERSION, IPK_SOURCE, "package version", ipkFile.getVersion(), Confidence.HIGH);
            dependency.addEvidence(VERSION, IPK_SOURCE, "version", ipkFile.getVersion().replaceAll("-r[0-9]+$", ""), Confidence.HIGHEST);
            final String homepage = ipkFile.getHomepage();
            dependency.setDescription(ipkFile.getDescription());
            dependency.setLicense(ipkFile.getLicense());
            if(homepage != null && !homepage.equals("")) {
                dependency.addEvidence(VENDOR, IPK_SOURCE, "organization url", homepage, Confidence.HIGHEST);
                dependency.addEvidence(PRODUCT, IPK_SOURCE, "organization url", homepage, Confidence.HIGHEST);
            }
        } catch (IOException | MalformedPackageURLException e) {
            throw new AnalysisException(e);
        }
    }


}
