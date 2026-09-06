package com.ksscanner.report;

import com.ksscanner.model.Finding;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;

public class CsvReportGenerator {

    public void generate(List<Finding> findings,
                         String outputFile)
            throws Exception {

        PrintWriter writer =
                new PrintWriter(new FileWriter(outputFile));

        writer.println(
                "Severity,Rule,Category,Confidence,CWE,OWASP,File,Line,Column,Message,Recommendation,Source,Sink,Snippet");

        for (Finding finding : findings) {

            String snippet = finding.getSnippet();

            if (snippet == null) {
                snippet = "";
            }

            snippet = snippet
                    .replace("\"", "\"\"")
                    .replace("\r", "")
                    .replace("\n", " ");

            writer.println(
                    "\"" + finding.getSeverity() + "\","
                    + "\"" + finding.getRule() + "\","
                    + "\"" + finding.getCategory() + "\","
                    + "\"" + finding.getConfidence() + "\","
                    + "\"" + finding.getCwe() + "\","
                    + "\"" + finding.getOwasp() + "\","
                    + "\"" + finding.getFile() + "\","
                    + "\"" + finding.getLine() + "\","
                    + "\"" + finding.getColumn() + "\","
                    + "\"" + finding.getMessage().replace("\"", "\"\"") + "\","
                    + "\"" + finding.getRecommendation().replace("\"", "\"\"") + "\","
                    + "\"" + finding.getSource().replace("\"", "\"\"") + "\","
                    + "\"" + finding.getSink().replace("\"", "\"\"") + "\","
                    + "\"" + snippet + "\""
            );
        }

        writer.close();
    }
}