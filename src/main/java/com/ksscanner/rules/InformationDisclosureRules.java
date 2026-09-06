package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class InformationDisclosureRules extends BaseRuleGroup {

    @Override
    public void scan(CompilationUnit cu,
                     Path file,
                     List<Finding> findings) {

        detectInternalIPs(cu, file, findings);
        detectInternalPaths(cu, file, findings);
        detectStackTraceExposure(cu, file, findings);
        detectDebugMode(cu, file, findings);
        detectDatabaseConnectionStrings(cu, file, findings);
        detectSensitiveLogging(cu, file, findings);
        detectEnvironmentVariableDisclosure(cu, file, findings);
        detectSystemPropertyDisclosure(cu, file, findings);
        detectVerboseErrorMessages(cu, file, findings);
    }

    private void detectInternalIPs(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.matches(".*192\\.168\\..*")
                    || value.matches(".*10\\..*")
                    || value.matches(".*172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-ID-001",
                        "Internal IP Disclosure",
                        "Information Disclosure",
                        "Medium",
                        "High",
                        "CWE-200",
                        "A01:2025",
                        "Internal network address exposed in source code."
                );
            }
        });
    }

    private void detectInternalPaths(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("C:\\")
                    || value.contains("/home/")
                    || value.contains("/opt/")
                    || value.contains("/var/")
                    || value.contains("/usr/")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-ID-002",
                        "Internal Path Disclosure",
                        "Information Disclosure",
                        "Medium",
                        "High",
                        "CWE-209",
                        "A01:2025",
                        "Internal filesystem path exposed."
                );
            }
        });
    }

    private void detectStackTraceExposure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("printStackTrace".equals(
                    call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-ID-003",
                        "Stack Trace Exposure",
                        "Information Disclosure",
                        "Medium",
                        "High",
                        "CWE-209",
                        "A09:2025",
                        "Stack trace may expose sensitive application details."
                );
            }
        });
    }

    private void detectDebugMode(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("debug=true")
                    || value.equals("debug")
                    || value.contains("devmode")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-ID-004",
                        "Debug Mode Enabled",
                        "Information Disclosure",
                        "Medium",
                        "Medium",
                        "CWE-489",
                        "A09:2025",
                        "Debug mode may expose sensitive information."
                );
            }
        });
    }

    private void detectDatabaseConnectionStrings(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("jdbc:")
                    || value.contains("mysql://")
                    || value.contains("postgresql://")
                    || value.contains("mongodb://")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-ID-005",
                        "Database Connection String Exposure",
                        "Information Disclosure",
                        "Medium",
                        "High",
                        "CWE-200",
                        "A01:2025",
                        "Database connection details exposed."
                );
            }
        });
    }

    private void detectSensitiveLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text =
                    call.toString().toLowerCase();

            if ((text.contains("password")
                    || text.contains("secret")
                    || text.contains("token")
                    || text.contains("apikey"))
                    &&
                    (text.contains("logger")
                            || text.contains("log.")
                            || text.contains("print"))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-ID-006",
                        "Sensitive Data Logged",
                        "Information Disclosure",
                        "High",
                        "High",
                        "CWE-532",
                        "A09:2025",
                        "Sensitive information written to logs."
                );
            }
        });
    }

    private void detectEnvironmentVariableDisclosure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("System.getenv")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-ID-007",
                        "Environment Variable Disclosure",
                        "Information Disclosure",
                        "Medium",
                        "Medium",
                        "CWE-497",
                        "A01:2025",
                        "Environment variable access detected."
                );
            }
        });
    }

    private void detectSystemPropertyDisclosure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("System.getProperty")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-ID-008",
                        "System Property Disclosure",
                        "Information Disclosure",
                        "Medium",
                        "Medium",
                        "CWE-497",
                        "A01:2025",
                        "System property access detected."
                );
            }
        });
    }

    private void detectVerboseErrorMessages(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("exception")
                    || value.contains("stacktrace")
                    || value.contains("sql error")
                    || value.contains("database error")
                    || value.contains("internal server error")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-ID-009",
                        "Verbose Error Message",
                        "Information Disclosure",
                        "Medium",
                        "Medium",
                        "CWE-209",
                        "A09:2025",
                        "Verbose error message may reveal internal details."
                );
            }
        });
    }
}