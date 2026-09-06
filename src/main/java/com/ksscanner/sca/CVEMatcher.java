package com.ksscanner.sca;

import java.util.ArrayList;
import java.util.List;

public class CVEMatcher {

    public List<CVERecord> match(
            List<Dependency> dependencies,
            List<CVERecord> database) {

        List<CVERecord> matches =
                new ArrayList<>();

        for (Dependency dependency : dependencies) {

            for (CVERecord cve : database) {

                boolean packageMatch =
                        dependency.getArtifactId()
                                .equalsIgnoreCase(
                                        cve.getPackageName());

                boolean versionMatch =
                        dependency.getVersion()
                                .equalsIgnoreCase(
                                        cve.getVersion());

                if (packageMatch && versionMatch) {

                    matches.add(cve);
                }
            }
        }

        return matches;
    }
}