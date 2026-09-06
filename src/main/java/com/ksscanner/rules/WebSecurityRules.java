package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class WebSecurityRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectCorsWildcard(cu, file, findings);
        detectCsrfDisabled(cu, file, findings);
        detectOpenRedirect(cu, file, findings);
        detectCookieSecurityIssues(cu, file, findings);
        detectSecurityHeaders(cu, file, findings);
        detectClickjackingIssues(cu, file, findings);
        detectHstsIssues(cu, file, findings);
    }

    private void detectCorsWildcard(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(AnnotationExpr.class).forEach(annotation -> {

            String text = annotation.toString();

            if (text.contains("@CrossOrigin")
                    && text.contains("*")) {

                addFinding(
                        findings,
                        file,
                        annotation,
                        "JAVA-WEB-001",
                        "Wildcard CORS Policy",
                        "Web Security",
                        "High",
                        "High",
                        "CWE-942",
                        "A05:2025",
                        "Cross-Origin Resource Sharing allows all origins."
                );
            }
        });
    }

    private void detectCsrfDisabled(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("csrf().disable()")
                || source.contains(".csrf(csrf -> csrf.disable())")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-003",
                    "CSRF Protection Disabled",
                    "Web Security",
                    "High",
                    "High",
                    "CWE-352",
                    "A05:2025",
                    "CSRF protection is disabled."
            );
        }
    }

    private void detectOpenRedirect(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if (text.contains("sendRedirect(")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-WEB-010",
                        "Potential Open Redirect",
                        "Web Security",
                        "High",
                        "Medium",
                        "CWE-601",
                        "A01:2025",
                        "Validate redirect targets before use."
                );
            }
        });
    }

    private void detectCookieSecurityIssues(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("setSecure(false)")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-007",
                    "Cookie Secure Flag Disabled",
                    "Web Security",
                    "Medium",
                    "High",
                    "CWE-614",
                    "A05:2025",
                    "Cookies transmitted over insecure channels."
            );
        }

        if (source.contains("setHttpOnly(false)")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-008",
                    "Cookie HttpOnly Disabled",
                    "Web Security",
                    "Medium",
                    "High",
                    "CWE-1004",
                    "A05:2025",
                    "Cookies accessible through client-side scripts."
            );
        }
    }

    private void detectSecurityHeaders(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (!source.contains("Content-Security-Policy")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-004",
                    "Missing CSP Header",
                    "Web Security",
                    "Medium",
                    "Low",
                    "CWE-693",
                    "A05:2025",
                    "Content Security Policy header not detected."
            );
        }
    }

    private void detectClickjackingIssues(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (!source.contains("X-Frame-Options")
                && !source.contains("frame-ancestors")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-005",
                    "Clickjacking Protection Missing",
                    "Web Security",
                    "Medium",
                    "Low",
                    "CWE-1021",
                    "A05:2025",
                    "Frame protection headers not detected."
            );
        }
    }

    private void detectHstsIssues(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (!source.contains("Strict-Transport-Security")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-WEB-006",
                    "HSTS Header Missing",
                    "Web Security",
                    "Medium",
                    "Low",
                    "CWE-319",
                    "A02:2025",
                    "HTTP Strict Transport Security header not detected."
            );
        }
    }
}