package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class SessionManagementRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectSessionCreation(cu, file, findings);
        detectSessionFixation(cu, file, findings);
        detectCookieFlags(cu, file, findings);
        detectSameSiteMissing(cu, file, findings);
        detectLongTimeout(cu, file, findings);
        detectUrlSessionTracking(cu, file, findings);
        detectSessionExposure(cu, file, findings);
        detectWeakSessionId(cu, file, findings);
    }

    private void detectSessionCreation(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("getSession(")
                    || call.toString().contains("getSession()")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-SESSION-001",
                        "Session Creation",
                        "Session Management",
                        "Medium",
                        "Medium",
                        "CWE-384",
                        "A07:2025",
                        "Review session handling implementation."
                );
            }
        });
    }

    private void detectSessionFixation(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (!source.contains("changeSessionId()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-002",
                    "Possible Session Fixation",
                    "Session Management",
                    "High",
                    "Low",
                    "CWE-384",
                    "A07:2025",
                    "No session ID regeneration detected."
            );
        }
    }

    private void detectCookieFlags(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("setSecure(false)")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-004",
                    "Cookie Secure Disabled",
                    "Session Management",
                    "Medium",
                    "High",
                    "CWE-614",
                    "A07:2025",
                    "Secure flag disabled."
            );
        }

        if (source.contains("setHttpOnly(false)")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-005",
                    "Cookie HttpOnly Disabled",
                    "Session Management",
                    "Medium",
                    "High",
                    "CWE-1004",
                    "A07:2025",
                    "HttpOnly flag disabled."
            );
        }
    }

    private void detectSameSiteMissing(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (!cu.toString().contains("SameSite")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-006",
                    "SameSite Cookie Not Detected",
                    "Session Management",
                    "Medium",
                    "Low",
                    "CWE-1275",
                    "A07:2025",
                    "Review cookie SameSite protection."
            );
        }
    }

    private void detectLongTimeout(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("3600")
                    || value.contains("7200")
                    || value.contains("86400")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SESSION-007",
                        "Long Session Timeout",
                        "Session Management",
                        "Medium",
                        "Low",
                        "CWE-613",
                        "A07:2025",
                        "Review session timeout duration."
                );
            }
        });
    }

    private void detectUrlSessionTracking(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("jsessionid")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-008",
                    "URL Session Tracking",
                    "Session Management",
                    "High",
                    "High",
                    "CWE-598",
                    "A07:2025",
                    "Session ID may be exposed in URL."
            );
        }
    }

    private void detectSessionExposure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("getId()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-009",
                    "Session Identifier Access",
                    "Session Management",
                    "Medium",
                    "Low",
                    "CWE-200",
                    "A01:2025",
                    "Review session ID handling."
            );
        }
    }

    private void detectWeakSessionId(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("random()")
                || source.contains("currenttimemillis()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SESSION-010",
                    "Weak Session Identifier Generation",
                    "Session Management",
                    "Medium",
                    "Medium",
                    "CWE-330",
                    "A07:2025",
                    "Use SecureRandom for session identifiers."
            );
        }
    }
}