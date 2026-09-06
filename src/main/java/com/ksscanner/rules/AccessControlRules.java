package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class AccessControlRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectHardcodedAdminRole(cu, file, findings);
        detectHardcodedRoles(cu, file, findings);
        detectPermitAll(cu, file, findings);
        detectDisabledSecurity(cu, file, findings);
        detectAdminEndpoints(cu, file, findings);
        detectIdorPatterns(cu, file, findings);
    }

   private void detectHardcodedAdminRole(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(StringLiteralExpr.class).forEach(expr -> {

        String value = expr.asString().toLowerCase();

        if (!value.equals("admin")
                && !value.equals("administrator")
                && !value.equals("superadmin")) {
            return;
        }

        expr.findAncestor(
                com.github.javaparser.ast.body.VariableDeclarator.class)
                .ifPresent(var -> {

                    String varName =
                            var.getNameAsString().toLowerCase();

                    if (varName.contains("role")
                            || varName.contains("authority")
                            || varName.contains("permission")) {

                        addFinding(
                                findings,
                                file,
                                expr,
                                "JAVA-AC-001",
                                "Hardcoded Administrative Role",
                                "Access Control",
                                "Medium",
                                "High",
                                "CWE-269",
                                "A01:2025",
                                "Hardcoded privileged role detected."
                        );
                    }
                });
    });
}

    private void detectHardcodedRoles(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    String[] roles = {
            "admin",
            "manager",
            "supervisor",
            "operator",
            "superadmin"
    };

    cu.findAll(StringLiteralExpr.class).forEach(expr -> {

        String value = expr.asString().toLowerCase();

        boolean roleMatch = false;

        for (String role : roles) {
            if (role.equals(value)) {
                roleMatch = true;
                break;
            }
        }

        if (!roleMatch) {
            return;
        }

        expr.findAncestor(
                com.github.javaparser.ast.body.VariableDeclarator.class)
                .ifPresent(var -> {

                    String varName =
                            var.getNameAsString().toLowerCase();

                    if (varName.contains("role")
                            || varName.contains("authority")) {

                        addFinding(
                                findings,
                                file,
                                expr,
                                "JAVA-AC-005",
                                "Hardcoded User Role",
                                "Access Control",
                                "Medium",
                                "Medium",
                                "CWE-269",
                                "A01:2025",
                                "Hardcoded authorization role detected."
                        );
                    }
                });
    });
}

    private void detectPermitAll(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(AnnotationExpr.class).forEach(annotation -> {

            if ("PermitAll".equals(
                    annotation.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        annotation,
                        "JAVA-AC-006",
                        "Permit All Configuration",
                        "Access Control",
                        "High",
                        "High",
                        "CWE-732",
                        "A01:2025",
                        "Endpoint accessible without authorization."
                );
            }
        });
    }

    private void detectDisabledSecurity(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(MethodCallExpr.class).forEach(call -> {

        String name =
                call.getNameAsString();

        if ("permitAll".equals(name)) {

            addFinding(
                    findings,
                    file,
                    call,
                    "JAVA-AC-007",
                    "Security Configuration Disabled",
                    "Access Control",
                    "High",
                    "High",
                    "CWE-862",
                    "A01:2025",
                    "permitAll() detected."
            );
        }

        if ("disable".equals(name)) {

            addFinding(
                    findings,
                    file,
                    call,
                    "JAVA-AC-007",
                    "Security Configuration Disabled",
                    "Access Control",
                    "High",
                    "Medium",
                    "CWE-862",
                    "A01:2025",
                    "Security control disabled."
            );
        }
    });
}

    private void detectAdminEndpoints(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(StringLiteralExpr.class).forEach(expr -> {

        String value =
                expr.asString().toLowerCase();

        if (value.startsWith("/admin")) {

            addFinding(
                    findings,
                    file,
                    expr,
                    "JAVA-AC-008",
                    "Administrative Endpoint",
                    "Access Control",
                    "Info",
                    "Low",
                    "CWE-285",
                    "A01:2025",
                    "Review authorization protecting admin endpoint."
            );
        }
    });
}

    private void detectIdorPatterns(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(MethodCallExpr.class).forEach(call -> {

        String name =
                call.getNameAsString().toLowerCase();

        if (name.equals("findbyid")
                || name.equals("getbyid")) {

            addFinding(
                    findings,
                    file,
                    call,
                    "JAVA-AC-004",
                    "Potential IDOR Review",
                    "Access Control",
                    "Low",
                    "Low",
                    "CWE-639",
                    "A01:2025",
                    "Verify ownership validation before resource access."
            );
        }
    });
}

    
}