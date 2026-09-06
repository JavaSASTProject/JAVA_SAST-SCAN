package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.TryStmt;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class ResourceRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectFileStreams(cu, file, findings);
        detectReaders(cu, file, findings);
        detectSockets(cu, file, findings);
        detectJdbcResources(cu, file, findings);
        detectExecutorService(cu, file, findings);
        detectScannerUsage(cu, file, findings);
        detectMissingTryWithResources(cu, file, findings);
    }

    private void detectFileStreams(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            String type = expr.getType().asString();

            if ("FileInputStream".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-RES-001",
                        "FileInputStream Resource",
                        "Resource Management",
                        "Medium",
                        "Medium",
                        "CWE-772",
                        "N/A",
                        "Verify FileInputStream is properly closed."
                );
            }

            if ("FileOutputStream".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-RES-002",
                        "FileOutputStream Resource",
                        "Resource Management",
                        "Medium",
                        "Medium",
                        "CWE-772",
                        "N/A",
                        "Verify FileOutputStream is properly closed."
                );
            }
        });
    }

    private void detectReaders(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            String type = expr.getType().asString();

            if ("BufferedReader".equals(type)
                    || "FileReader".equals(type)
                    || "InputStreamReader".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-RES-003",
                        "Reader Resource",
                        "Resource Management",
                        "Medium",
                        "Medium",
                        "CWE-772",
                        "N/A",
                        "Verify reader resource is properly closed."
                );
            }
        });
    }

    private void detectSockets(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            String type = expr.getType().asString();

            if ("Socket".equals(type)
                    || "ServerSocket".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-RES-004",
                        "Socket Resource",
                        "Resource Management",
                        "High",
                        "Medium",
                        "CWE-772",
                        "N/A",
                        "Verify socket is properly closed."
                );
            }
        });
    }

    private void detectJdbcResources(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("Connection ")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-RES-005",
                    "JDBC Connection Resource",
                    "Resource Management",
                    "Medium",
                    "Medium",
                    "CWE-772",
                    "N/A",
                    "Verify JDBC connection is properly closed."
            );
        }

        if (source.contains("Statement ")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-RES-006",
                    "Statement Resource",
                    "Resource Management",
                    "Medium",
                    "Medium",
                    "CWE-772",
                    "N/A",
                    "Verify Statement is properly closed."
            );
        }

        if (source.contains("ResultSet ")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-RES-007",
                    "ResultSet Resource",
                    "Resource Management",
                    "Medium",
                    "Medium",
                    "CWE-772",
                    "N/A",
                    "Verify ResultSet is properly closed."
            );
        }
    }

    private void detectExecutorService(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("ExecutorService")
                || source.contains("Executors.new")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-RES-008",
                    "ExecutorService Usage",
                    "Resource Management",
                    "Medium",
                    "Medium",
                    "CWE-772",
                    "N/A",
                    "Verify ExecutorService shutdown() is called."
            );
        }
    }

    private void detectScannerUsage(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            if ("Scanner".equals(
                    expr.getType().asString())) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-RES-010",
                        "Scanner Resource",
                        "Resource Management",
                        "Low",
                        "Medium",
                        "CWE-772",
                        "N/A",
                        "Verify Scanner is properly closed."
                );
            }
        });
    }

    private void detectMissingTryWithResources(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        boolean hasTryWithResources =
                cu.findAll(TryStmt.class)
                        .stream()
                        .anyMatch(t ->
                                !t.getResources().isEmpty());

        if (!hasTryWithResources) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-RES-009",
                    "Missing Try-With-Resources",
                    "Resource Management",
                    "Low",
                    "Low",
                    "CWE-772",
                    "N/A",
                    "Consider using try-with-resources for automatic resource cleanup."
            );
        }
    }
}