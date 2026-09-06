package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class InjectionRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectSqlInjection(cu, file, findings);
        detectCommandInjection(cu, file, findings);
        detectRuntimeExec(cu, file, findings);
        detectProcessBuilder(cu, file, findings);
        detectLdapInjection(cu, file, findings);
        detectXPathInjection(cu, file, findings);
        detectNoSqlInjection(cu, file, findings);
    }

    private void detectSqlInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(BinaryExpr.class).forEach(expr -> {

            String code = expr.toString().toLowerCase();

            if ((code.contains("select ")
                    || code.contains("insert ")
                    || code.contains("update ")
                    || code.contains("delete "))
                    && code.contains("+")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-INJ-001",
                        "Potential SQL Injection",
                        "Injection",
                        "High",
                        "Medium",
                        "CWE-89",
                        "A03:2025",
                        "Dynamic SQL query construction detected."
                );
            }
        });
    }

    private void detectCommandInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if (text.contains("exec(")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-INJ-002",
                        "Potential Command Injection",
                        "Injection",
                        "High",
                        "High",
                        "CWE-78",
                        "A03:2025",
                        "OS command execution detected."
                );
            }
        });
    }

    private void detectRuntimeExec(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("exec".equals(call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-INJ-007",
                        "Runtime.exec Usage",
                        "Injection",
                        "High",
                        "High",
                        "CWE-78",
                        "A03:2025",
                        "Runtime.exec can lead to command injection."
                );
            }
        });
    }

    private void detectProcessBuilder(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("ProcessBuilder")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-INJ-008",
                    "ProcessBuilder Usage",
                    "Injection",
                    "Medium",
                    "Medium",
                    "CWE-78",
                    "A03:2025",
                    "Review command construction for injection risks."
            );
        }
    }

    private void detectLdapInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString().toLowerCase();

            if (value.contains("ldap")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-INJ-003",
                        "LDAP Injection Risk",
                        "Injection",
                        "High",
                        "Medium",
                        "CWE-90",
                        "A03:2025",
                        "LDAP query construction detected."
                );
            }
        });
    }

    private void detectXPathInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("XPath")
                || source.contains("XPathExpression")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-INJ-004",
                    "XPath Injection Risk",
                    "Injection",
                    "High",
                    "Medium",
                    "CWE-643",
                    "A03:2025",
                    "XPath query evaluation detected."
            );
        }
    }

    private void detectNoSqlInjection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("mongodb")
                || source.contains("mongo")
                || source.contains("document.parse(")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-INJ-005",
                    "NoSQL Injection Risk",
                    "Injection",
                    "High",
                    "Medium",
                    "CWE-943",
                    "A03:2025",
                    "MongoDB query construction detected."
            );
        }
    }
}