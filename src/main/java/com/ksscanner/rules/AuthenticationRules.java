package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class AuthenticationRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectHardcodedAdminRole(cu, file, findings);
        detectHardcodedPassword(cu, file, findings);
        detectWeakPasswords(cu, file, findings);
        detectPlaintextPasswords(cu, file, findings);
        detectPasswordLogging(cu, file, findings);
        detectAuthenticationBypass(cu, file, findings);
        detectWeakSessionIdentifiers(cu, file, findings);
    }

    private void detectHardcodedAdminRole(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString().toLowerCase();

            if ("admin".equals(value)
                    || "administrator".equals(value)
                    || "superadmin".equals(value)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-AUTH-001",
                        "Hardcoded Administrative Role",
                        "Authentication",
                        "Medium",
                        "High",
                        "CWE-269",
                        "A07:2025",
                        "Hardcoded privileged role detected."
                );
            }
        });
    }

    private void detectHardcodedPassword(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(VariableDeclarator.class).forEach(var -> {

            String name =
                    var.getNameAsString().toLowerCase();

            if ((name.contains("password")
                    || name.contains("passwd")
                    || name.contains("pwd"))
                    && var.getInitializer().isPresent()
                    && var.getInitializer().get()
                    instanceof StringLiteralExpr) {

                addFinding(
                        findings,
                        file,
                        var,
                        "JAVA-AUTH-002",
                        "Hardcoded Password",
                        "Authentication",
                        "High",
                        "High",
                        "CWE-798",
                        "A07:2025",
                        "Hardcoded password detected."
                );
            }
        });
    }

    private void detectWeakPasswords(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        String[] weakPasswords = {
                "admin",
                "password",
                "123456",
                "welcome",
                "root",
                "test"
        };

        for (String weak : weakPasswords) {

            if (source.contains("\"" + weak + "\"")) {

                addFinding(
                        findings,
                        file,
                        cu,
                        "JAVA-AUTH-003",
                        "Weak Password",
                        "Authentication",
                        "Medium",
                        "Medium",
                        "CWE-521",
                        "A07:2025",
                        "Weak password value detected."
                );
            }
        }
    }

    private void detectPlaintextPasswords(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(BinaryExpr.class).forEach(expr -> {

            String code =
                    expr.toString().toLowerCase();

            if (code.contains("password")
                    && code.contains("=")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-AUTH-008",
                        "Plaintext Password Storage",
                        "Authentication",
                        "High",
                        "Medium",
                        "CWE-256",
                        "A07:2025",
                        "Password appears stored in plaintext."
                );
            }
        });
    }

    private void detectPasswordLogging(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text =
                    call.toString().toLowerCase();

            if ((text.contains("password")
                    || text.contains("passwd"))
                    &&
                    (text.contains("logger")
                            || text.contains("log.")
                            || text.contains("print"))) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-AUTH-009",
                        "Password Logged",
                        "Authentication",
                        "High",
                        "High",
                        "CWE-532",
                        "A09:2025",
                        "Password written to logs."
                );
            }
        });
    }

    private void detectAuthenticationBypass(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (source.contains("if(true)")
                || source.contains("authenticated=true")
                || source.contains("isauthenticated=true")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-AUTH-007",
                    "Authentication Bypass Pattern",
                    "Authentication",
                    "High",
                    "Medium",
                    "CWE-287",
                    "A07:2025",
                    "Potential authentication bypass logic detected."
            );
        }
    }

    private void detectWeakSessionIdentifiers(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (source.contains("sessionid")
                && source.contains("random()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-AUTH-010",
                    "Weak Session Identifier",
                    "Authentication",
                    "Medium",
                    "Medium",
                    "CWE-330",
                    "A07:2025",
                    "Predictable session identifier generation."
            );
        }
    }
}