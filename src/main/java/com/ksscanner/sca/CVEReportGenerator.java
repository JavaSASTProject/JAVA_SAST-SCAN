package com.ksscanner.sca;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;

public class CVEReportGenerator {

    public void generate(
            List<CVERecord> cves,
            String outputFile)
            throws Exception {

        PrintWriter writer =
                new PrintWriter(
                        new FileWriter(outputFile));

        writer.println(
                "CVE,Package,Version,Severity,CVSS,Description,Recommendation,Reference");

        for (CVERecord cve : cves) {

            writer.println(
                    "\"" + cve.getCve() + "\","
                    + "\"" + cve.getPackageName() + "\","
                    + "\"" + cve.getVersion() + "\","
                    + "\"" + cve.getSeverity() + "\","
                    + "\"" + cve.getCvss() + "\","
                    + "\"" + cve.getDescription().replace("\"", "\"\"") + "\","
                    + "\"" + cve.getRecommendation().replace("\"", "\"\"") + "\","
                    + "\"" + cve.getReference() + "\""
            );
        }

        writer.close();
    }
}