package com.ksscanner;

import com.github.javaparser.ast.CompilationUnit;
import com.ksscanner.engine.RuleManager;
import com.ksscanner.model.Finding;
import com.ksscanner.model.JavaFileInfo;
import com.ksscanner.parser.JavaFileParser;
import com.ksscanner.report.CsvReportGenerator;
import com.ksscanner.report.HtmlReportGenerator;
import com.ksscanner.scanner.DirectoryScanner;
import com.ksscanner.visitor.JavaAstVisitor;
import com.ksscanner.sca.Dependency;
import com.ksscanner.sca.DependencyAnalyzer;
import com.ksscanner.sca.SBOMGenerator;
import com.ksscanner.sca.CVERecord;
import com.ksscanner.sca.CVEDatabaseLoader;
import com.ksscanner.sca.CVEMatcher;
import com.ksscanner.sca.CVEReportGenerator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {

        System.out.println("================================");
        System.out.println(" KSScanner v1.0");
        System.out.println(" Java Static Code Analyzer");
        System.out.println("================================");

        if (args.length == 0) {

            System.out.println();
            System.out.println("Usage:");
            System.out.println(
                    "java -jar KSScanner.jar <project-path>");
            System.out.println();

            return;
        }

        String projectPath = args[0];

        Path project = Path.of(projectPath);

        if (!Files.exists(project)) {

            System.err.println();
            System.err.println(
                    "[ERROR] Project path does not exist:");
            System.err.println(projectPath);

            return;
        }

        if (!Files.isDirectory(project)) {

            System.err.println();
            System.err.println(
                    "[ERROR] Project path is not a directory:");
            System.err.println(projectPath);

            return;
        }

        DirectoryScanner scanner =
                new DirectoryScanner();

        JavaFileParser parser =
                new JavaFileParser();

        RuleManager manager =
                new RuleManager();

        List<Finding> allFindings =
                new ArrayList<>();

        try {

            List<Path> files =
                    scanner.scan(projectPath);

            System.out.println();
            System.out.println(
                    "Project Path : "
                            + project.toAbsolutePath());

            System.out.println(
                    "Files Found  : "
                            + files.size());

            System.out.println(
                    "Rule Groups  : "
                            + manager.getRuleGroupCount());

            for (Path file : files) {

                try {

                    JavaFileInfo info =
                            parser.parse(file.toFile());

                    CompilationUnit cu =
                            parser.parseAst(
                                    file.toFile());

                    JavaAstVisitor visitor =
                            new JavaAstVisitor();

                    visitor.visit(cu, null);

                    List<Finding> findings =
                            manager.analyze(
                                    cu,
                                    file.getFileName()
                                            .toString(),
                                    file);

                    allFindings.addAll(findings);

                } catch (Exception fileException) {

                    System.err.println();

                    System.err.println(
                            "[WARNING] Could not scan file:");

                    System.err.println(file);

                    System.err.println(
                            "Reason: "
                                    + fileException
                                    .getMessage());
                }
            }

// ========================================
// SCA - Dependency Discovery
// ========================================

DependencyAnalyzer dependencyAnalyzer =
        new DependencyAnalyzer();

List<Dependency> dependencies =
        dependencyAnalyzer.analyze(project);

System.out.println();
System.out.println("================================");
System.out.println(" SCA Summary");
System.out.println("================================");

System.out.println(
        "Dependencies Found : "
                + dependencies.size());

// ========================================
// SBOM Generation
// ========================================

SBOMGenerator sbomGenerator =
        new SBOMGenerator();

sbomGenerator.generate(
        dependencies,
        "KSScanner_SBOM.json");

for (Dependency dependency : dependencies) {

    System.out.println(
            " - " + dependency);
}

        CVEDatabaseLoader loader =
        new CVEDatabaseLoader();

List<CVERecord> database =
        loader.load("cve-db.csv");

CVEMatcher matcher =
        new CVEMatcher();

List<CVERecord> matches =
        matcher.match(
                dependencies,
                database);
CVEReportGenerator cveReport =
        new CVEReportGenerator();

cveReport.generate(
        matches,
        "KSScanner_CVE_Report.csv");

System.out.println();
System.out.println("================================");
System.out.println(" CVE Summary");
System.out.println("================================");

System.out.println(
        "Vulnerabilities Found : "
                + matches.size());

for (CVERecord cve : matches) {

    System.out.println("--------------------------------");

    System.out.println(
            "CVE            : "
                    + cve.getCve());

    System.out.println(
            "Package        : "
                    + cve.getPackageName());

    System.out.println(
            "Version        : "
                    + cve.getVersion());

    System.out.println(
            "Severity       : "
                    + cve.getSeverity());

    System.out.println(
            "CVSS           : "
                    + cve.getCvss());

    System.out.println(
            "Description    : "
                    + cve.getDescription());

    System.out.println(
            "Recommendation : "
                    + cve.getRecommendation());

    System.out.println(
            "Reference      : "
                    + cve.getReference());
}


            System.out.println();
            System.out.println(
                    "================================");

            System.out.println(
                    " Scan Summary");

            System.out.println(
                    "================================");

            System.out.println(
                    "Project       : "
                            + project.toAbsolutePath());

            System.out.println(
                    "Files Scanned : "
                            + files.size());

            System.out.println(
                    "Rule Groups   : "
                            + manager.getRuleGroupCount());

            System.out.println(
                    "Total Findings: "
                            + allFindings.size());

            CsvReportGenerator csv =
                    new CsvReportGenerator();

            csv.generate(
                    allFindings,
                    "KSScanner_Report.csv");

            HtmlReportGenerator html =
                    new HtmlReportGenerator();

            html.generate(
                    allFindings,
                    "KSScanner_Report.html");

            System.out.println();

            System.out.println(
                    "CSV Report  : "
                            + Path.of(
                            "KSScanner_Report.csv")
                            .toAbsolutePath());

            System.out.println(
                    "HTML Report : "
                            + Path.of(
                            "KSScanner_Report.html")
                            .toAbsolutePath());
            System.out.println(
        "SBOM Report : "
                + Path.of(
                "KSScanner_SBOM.json")
                .toAbsolutePath());

        System.out.println(
        "CVE Report  : "
                + Path.of(
                "KSScanner_CVE_Report.csv")
                .toAbsolutePath());

            System.out.println();

            System.out.println(
                    "Scan completed successfully.");

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "[ERROR] Scanner failed.");

            System.err.println(
                    "Reason: "
                            + e.getMessage());

            e.printStackTrace();
        }
    }
}