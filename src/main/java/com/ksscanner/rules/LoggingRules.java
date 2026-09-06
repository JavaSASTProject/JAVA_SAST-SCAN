package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class LoggingRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectSensitiveLogging(cu, file, findings);
        detectPasswordLogging(cu, file, findings);
        detectTokenLogging(cu, file, findings);
        detectPrintStackTrace(cu, file, findings);
        detectDebugLogging(cu, file, findings);
        detectLogInjection(cu, file, findings);
        detectConsoleLogging(cu, file, findings);
        detectSwallowedExceptionWithoutLogging(cu, file, findings);
    }

    private void detectSensitiveLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString().toLowerCase();

            if ((text.contains("password")
                    || text.contains("secret")
                    || text.contains("token")
                    || text.contains("apikey"))
                    &&
                    (text.contains("logger.")
                            || text.contains("log.")
                            || text.contains("print"))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-LOG-001",
                        "Sensitive Data Logged",
                        "Logging",
                        "High",
                        "High",
                        "CWE-532",
                        "A09:2025",
                        "Sensitive information written to logs."
                );
            }
        });
    }

    private void detectPasswordLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString().toLowerCase();

            if (text.contains("password")
                    &&
                    (text.contains("logger")
                            || text.contains("log."))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-LOG-002",
                        "Password Logged",
                        "Logging",
                        "High",
                        "High",
                        "CWE-532",
                        "A09:2025",
                        "Password value appears in logs."
                );
            }
        });
    }

    private void detectTokenLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString().toLowerCase();

            if ((text.contains("token")
                    || text.contains("apikey")
                    || text.contains("secret"))
                    &&
                    (text.contains("logger")
                            || text.contains("log."))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-LOG-003",
                        "Token/API Key Logged",
                        "Logging",
                        "High",
                        "High",
                        "CWE-532",
                        "A09:2025",
                        "Authentication token exposed in logs."
                );
            }
        });
    }

    private void detectPrintStackTrace(
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
                        "JAVA-LOG-004",
                        "printStackTrace Usage",
                        "Logging",
                        "Medium",
                        "High",
                        "CWE-209",
                        "A09:2025",
                        "Stack trace may expose internal details."
                );
            }
        });
    }

    private void detectDebugLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("debug")
                    || value.contains("trace")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-LOG-005",
                        "Debug Logging Enabled",
                        "Logging",
                        "Low",
                        "Medium",
                        "CWE-489",
                        "A09:2025",
                        "Review debug logging in production code."
                );
            }
        });
    }

    private void detectLogInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if ((text.contains("logger")
                    || text.contains("log."))
                    &&
                    (text.contains("request")
                            || text.contains("input")
                            || text.contains("parameter"))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-LOG-006",
                        "Potential Log Injection",
                        "Logging",
                        "Medium",
                        "Medium",
                        "CWE-117",
                        "A09:2025",
                        "Untrusted input written directly to logs."
                );
            }
        });
    }

    private void detectConsoleLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if (text.contains("System.out.println")
                    || text.contains("System.err.println")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-LOG-010",
                        "Console Logging",
                        "Logging",
                        "Low",
                        "High",
                        "CWE-489",
                        "A09:2025",
                        "Use a centralized logging framework."
                );
            }
        });
    }

    private void detectSwallowedExceptionWithoutLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            if (catchClause.getBody().isEmpty()) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-LOG-009",
                        "Exception Not Logged",
                        "Logging",
                        "Medium",
                        "Medium",
                        "CWE-778",
                        "A09:2025",
                        "Exception handled without logging."
                );
            }
        });
    }
}