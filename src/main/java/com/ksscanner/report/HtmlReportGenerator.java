package com.ksscanner.report;

import com.ksscanner.model.Finding;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;

public class HtmlReportGenerator {

    public void generate(List<Finding> findings,
                         String outputFile)
            throws Exception {

        int high = 0;
        int medium = 0;
        int low = 0;

        for (Finding f : findings) {

            String severity = f.getSeverity();

            if ("HIGH".equalsIgnoreCase(severity)) {
                high++;
            } else if ("MEDIUM".equalsIgnoreCase(severity)) {
                medium++;
            } else if ("LOW".equalsIgnoreCase(severity)) {
                low++;
            }
        }

        PrintWriter writer =
                new PrintWriter(new FileWriter(outputFile));

        writer.println("<!DOCTYPE html>");
        writer.println("<html>");
        writer.println("<head>");
        writer.println("<meta charset='UTF-8'>");
        writer.println("<title>KSScanner Security Report</title>");

        writer.println("<style>");
        writer.println("body { font-family: Arial, sans-serif; margin: 20px; }");
        writer.println("h1 { color: #333; }");
        writer.println("table { border-collapse: collapse; width: 100%; }");
        writer.println("th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }");
        writer.println("th { background-color: #f2f2f2; }");
        writer.println("tr:nth-child(even) { background-color: #fafafa; }");
        writer.println("pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; }");

        writer.println(".high { background-color: #ffdddd; }");
        writer.println(".medium { background-color: #fff4cc; }");
        writer.println(".low { background-color: #ddffdd; }");

        writer.println(".summary {");
        writer.println("padding:10px;");
        writer.println("border:1px solid #ddd;");
        writer.println("margin-bottom:20px;");
        writer.println("background:#f9f9f9;");
        writer.println("}");

        writer.println("</style>");
        writer.println("</head>");
        writer.println("<body>");

        writer.println("<h1>KSScanner Security Report</h1>");

        writer.println("<div class='summary'>");
        writer.println("<h2>Summary</h2>");
        writer.println("<p><strong>Total Findings:</strong> "
                + findings.size() + "</p>");
        writer.println("<p><strong>High:</strong> "
                + high + "</p>");
        writer.println("<p><strong>Medium:</strong> "
                + medium + "</p>");
        writer.println("<p><strong>Low:</strong> "
                + low + "</p>");
        writer.println("</div>");

        writer.println("<h2>Findings</h2>");

        writer.println("<table>");

        writer.println(
                "<tr>"
                        + "<th>Severity</th>"
                        + "<th>Rule</th>"
                        + "<th>Category</th>"
                        + "<th>Confidence</th>"
                        + "<th>CWE</th>"
                        + "<th>OWASP</th>"
                        + "<th>File</th>"
                        + "<th>Line</th>"
                        + "<th>Column</th>"
                        + "<th>Message</th>"
                        + "<th>Recommendation</th>"
                        + "<th>Source</th>"
                        + "<th>Sink</th>"
                        + "<th>Snippet</th>"
                        + "</tr>");

        for (Finding finding : findings) {

            String severityClass = "";

            if ("HIGH".equalsIgnoreCase(finding.getSeverity())) {
                severityClass = "high";
            } else if ("MEDIUM".equalsIgnoreCase(finding.getSeverity())) {
                severityClass = "medium";
            } else if ("LOW".equalsIgnoreCase(finding.getSeverity())) {
                severityClass = "low";
            }

            writer.println(
                    "<tr class='" + severityClass + "'>"
                            + "<td>" + escapeHtml(finding.getSeverity()) + "</td>"
                            + "<td>" + escapeHtml(finding.getRule()) + "</td>"
                            + "<td>" + escapeHtml(finding.getCategory()) + "</td>"
                            + "<td>" + escapeHtml(finding.getConfidence()) + "</td>"
                            + "<td>" + escapeHtml(finding.getCwe()) + "</td>"
                            + "<td>" + escapeHtml(finding.getOwasp()) + "</td>"
                            + "<td>" + escapeHtml(finding.getFile()) + "</td>"
                            + "<td>" + finding.getLine() + "</td>"
                            + "<td>" + finding.getColumn() + "</td>"
                            + "<td>" + escapeHtml(finding.getMessage()) + "</td>"
                            + "<td>" + escapeHtml(finding.getRecommendation()) + "</td>"
                            + "<td>" + escapeHtml(finding.getSource()) + "</td>"
                            + "<td>" + escapeHtml(finding.getSink()) + "</td>"
                            + "<td><pre>"
                            + escapeHtml(finding.getSnippet())
                            + "</pre></td>"
                            + "</tr>"
            );
        }

        writer.println("</table>");

        writer.println("<br/>");
        writer.println("<hr/>");
        writer.println("<p>Generated by KSScanner</p>");

        writer.println("</body>");
        writer.println("</html>");

        writer.close();
    }

    private String escapeHtml(String value) {

        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}