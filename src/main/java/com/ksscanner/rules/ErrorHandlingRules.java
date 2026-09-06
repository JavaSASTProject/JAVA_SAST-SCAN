package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class ErrorHandlingRules extends BaseRuleGroup {

    @Override
    protected void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectEmptyCatch(cu, file, findings);
        detectGenericException(cu, file, findings);
        detectPrintStackTrace(cu, file, findings);
        detectSystemOutLogging(cu, file, findings);
        detectExceptionDisclosure(cu, file, findings);
        detectIgnoredExceptions(cu, file, findings);
        detectRuntimeException(cu, file, findings);
    }

    private void detectEmptyCatch(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            if (catchClause.getBody().isEmpty()) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-ERR-001",
                        "Empty Catch Block",
                        "Error Handling",
                        "Medium",
                        "High",
                        "CWE-390",
                        "A05:2025",
                        "Exception is caught but not handled."
                );
            }
        });
    }

    private void detectGenericException(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            String type =
                    catchClause.getParameter()
                               .getType()
                               .asString();

            if ("Exception".equals(type)
                    || "Throwable".equals(type)) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-ERR-002",
                        "Generic Exception Handling",
                        "Error Handling",
                        "Medium",
                        "High",
                        "CWE-396",
                        "A05:2025",
                        "Avoid catching Exception or Throwable."
                );
            }
        });
    }

    private void detectPrintStackTrace(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("printStackTrace")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-ERR-003",
                        "printStackTrace Usage",
                        "Error Handling",
                        "Medium",
                        "High",
                        "CWE-209",
                        "A05:2025",
                        "Stack traces may expose sensitive information."
                );
            }
        });
    }

    private void detectSystemOutLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("System.out.println")
                || source.contains("System.err.println")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-ERR-004",
                    "Console Error Logging",
                    "Error Handling",
                    "Low",
                    "Medium",
                    "CWE-778",
                    "A09:2025",
                    "Use a logging framework instead of console output."
            );
        }
    }

    private void detectExceptionDisclosure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("getMessage()")
                || source.contains("getLocalizedMessage()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-ERR-005",
                    "Exception Message Disclosure",
                    "Error Handling",
                    "Medium",
                    "Medium",
                    "CWE-209",
                    "A05:2025",
                    "Exception details may be disclosed."
            );
        }
    }

    private void detectIgnoredExceptions(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            String body = catchClause.getBody().toString();

            if (body.contains("// ignore")
                    || body.contains("// ignored")
                    || body.trim().equals("{ }")
                    || body.trim().equals("{}")) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-ERR-006",
                        "Ignored Exception",
                        "Error Handling",
                        "Medium",
                        "High",
                        "CWE-391",
                        "A05:2025",
                        "Exception is intentionally ignored."
                );
            }
        });
    }

    private void detectRuntimeException(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ThrowStmt.class).forEach(throwStmt -> {

            String text = throwStmt.toString();

            if (text.contains("RuntimeException")) {

                addFinding(
                        findings,
                        file,
                        throwStmt,
                        "JAVA-ERR-007",
                        "RuntimeException Throw",
                        "Error Handling",
                        "Low",
                        "Medium",
                        "CWE-397",
                        "A05:2025",
                        "Review RuntimeException usage."
                );
            }
        });
    }
}