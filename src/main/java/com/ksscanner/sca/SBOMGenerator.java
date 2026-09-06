package com.ksscanner.sca;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;

public class SBOMGenerator {

    public void generate(
            List<Dependency> dependencies,
            String outputFile)
            throws Exception {

        PrintWriter writer =
                new PrintWriter(
                        new FileWriter(outputFile));

        writer.println("{");
        writer.println("  \"bomFormat\": \"CycloneDX\",");
        writer.println("  \"specVersion\": \"1.5\",");
        writer.println("  \"version\": 1,");
        writer.println("  \"components\": [");

        for (int i = 0;
             i < dependencies.size();
             i++) {

            Dependency d =
                    dependencies.get(i);

            writer.println("    {");
            writer.println("      \"type\": \"library\",");
            writer.println("      \"group\": \"" +
                    escape(d.getGroupId()) + "\",");
            writer.println("      \"name\": \"" +
                    escape(d.getArtifactId()) + "\",");
            writer.println("      \"version\": \"" +
                    escape(d.getVersion()) + "\",");
            writer.println("      \"purl\": \"" +
                    escape(d.getPurl()) + "\"");
            writer.print("    }");

            if (i < dependencies.size() - 1) {
                writer.println(",");
            } else {
                writer.println();
            }
        }

        writer.println("  ]");
        writer.println("}");

        writer.close();
    }

    private String escape(String value) {

        if (value == null) {
            return "";
        }

        return value.replace("\"", "\\\"");
    }
}