package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class PortabilityRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectWindowsPaths(cu, file, findings);
        detectLinuxPaths(cu, file, findings);
        detectFileSeparatorUsage(cu, file, findings);
        detectLineSeparatorUsage(cu, file, findings);
        detectOsSpecificLogic(cu, file, findings);
        detectPlatformCommands(cu, file, findings);
        detectDriveLetters(cu, file, findings);
        detectAbsolutePaths(cu, file, findings);
        detectTempDirectoryUsage(cu, file, findings);
    }

    private void detectWindowsPaths(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("C:\\")
                    || value.contains("D:\\")
                    || value.contains("\\Users\\")
                    || value.contains("\\Program Files\\")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-PORT-001",
                        "Hardcoded Windows Path",
                        "Portability",
                        "Low",
                        "High",
                        "CWE-1104",
                        "N/A",
                        "Hardcoded Windows-specific path detected."
                );
            }
        });
    }

    private void detectLinuxPaths(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.startsWith("/home/")
                    || value.startsWith("/var/")
                    || value.startsWith("/opt/")
                    || value.startsWith("/usr/")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-PORT-002",
                        "Hardcoded Linux Path",
                        "Portability",
                        "Low",
                        "High",
                        "CWE-1104",
                        "N/A",
                        "Hardcoded Linux-specific path detected."
                );
            }
        });
    }

    private void detectFileSeparatorUsage(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("\"\\\\\"")
                || source.contains("\"/\"")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-PORT-003",
                    "Hardcoded File Separator",
                    "Portability",
                    "Low",
                    "Medium",
                    "CWE-1104",
                    "N/A",
                    "Use File.separator instead."
            );
        }
    }

    private void detectLineSeparatorUsage(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("\\r\\n")
                || source.contains("\\n")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-PORT-004",
                    "Hardcoded Line Separator",
                    "Portability",
                    "Low",
                    "Medium",
                    "CWE-1104",
                    "N/A",
                    "Use System.lineSeparator()."
            );
        }
    }

    private void detectOsSpecificLogic(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if (text.contains("System.getProperty(\"os.name\")")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-PORT-005",
                        "OS Specific Logic",
                        "Portability",
                        "Low",
                        "Medium",
                        "CWE-1104",
                        "N/A",
                        "Application behavior depends on operating system."
                );
            }
        });
    }

    private void detectPlatformCommands(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("cmd.exe")
                || source.contains("/bin/sh")
                || source.contains("powershell")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-PORT-006",
                    "Platform Specific Command",
                    "Portability",
                    "Medium",
                    "High",
                    "CWE-1104",
                    "N/A",
                    "Platform dependent command execution detected."
            );
        }
    }

    private void detectDriveLetters(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.matches("^[A-Z]:.*")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-PORT-007",
                        "Hardcoded Drive Letter",
                        "Portability",
                        "Low",
                        "High",
                        "CWE-1104",
                        "N/A",
                        "Drive letter dependency detected."
                );
            }
        });
    }

    private void detectAbsolutePaths(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.startsWith("/")
                    || value.matches("^[A-Z]:.*")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-PORT-009",
                        "Absolute Path Usage",
                        "Portability",
                        "Low",
                        "Medium",
                        "CWE-1104",
                        "N/A",
                        "Absolute path reduces portability."
                );
            }
        });
    }

    private void detectTempDirectoryUsage(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("java.io.tmpdir")
                || source.contains("/tmp/")
                || source.contains("\\temp\\")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-PORT-010",
                    "Platform Dependent Temp Directory",
                    "Portability",
                    "Low",
                    "Medium",
                    "CWE-1104",
                    "N/A",
                    "Temporary directory dependency detected."
            );
        }
    }
}