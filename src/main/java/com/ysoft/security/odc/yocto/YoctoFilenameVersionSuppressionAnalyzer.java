package com.ysoft.security.odc.yocto;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AbstractAnalyzer;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import static org.owasp.dependencycheck.dependency.EvidenceType.*;

/**
 * FileNameAnalyzer tries to get the version from file name. The problem is that it includes “-r0” or something similar from distribution, which is not
 * much relevant for ODC. This analyzer removes the version added by FileNameAnalyzer if YOCTO analyzer has added some version evidence.
 */
public class YoctoFilenameVersionSuppressionAnalyzer extends AbstractAnalyzer {

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return AbstractYoctoAnalyzer.YOCTO_ANALYZER_KEY;
    }

    @Override
    public String getName() {
        return "YOCTO filename version suppression";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.POST_INFORMATION_COLLECTION;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        cleanEvidence(dependency, VERSION);
        cleanEvidence(dependency, PRODUCT);
        cleanEvidence(dependency, VENDOR);
    }

    private static void cleanEvidence(Dependency dependency, EvidenceType evidenceType) {
        if(dependency.getEvidence(evidenceType).stream().anyMatch(x -> x.getSource().equals(AbstractYoctoAnalyzer.IPK_SOURCE))){
            dependency.getEvidence(evidenceType).stream().filter(item -> item.getSource().equals("file")).forEach(evidence -> dependency.removeEvidence(evidenceType, evidence));
        }
    }
}
