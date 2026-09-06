package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class SSRFRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectUrlCreation(cu, file, findings);
        detectUrlConnection(cu, file, findings);
        detectHttpUrlConnection(cu, file, findings);
        detectRestTemplate(cu, file, findings);
        detectWebClient(cu, file, findings);
        detectOkHttp(cu, file, findings);
        detectApacheHttpClient(cu, file, findings);
        detectOpenRedirect(cu, file, findings);
        detectInternalAddresses(cu, file, findings);
        detectMetadataEndpoints(cu, file, findings);
    }

    private void detectUrlCreation(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            if ("URL".equals(expr.getType().asString())) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SSRF-001",
                        "URL Construction Detected",
                        "SSRF",
                        "High",
                        "Medium",
                        "CWE-918",
                        "A10:2025",
                        "Review URL source to ensure untrusted input is validated."
                );
            }
        });
    }

    private void detectUrlConnection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("URLConnection")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-002",
                    "URLConnection Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "URLConnection can be abused for SSRF."
            );
        }
    }

    private void detectHttpUrlConnection(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("HttpURLConnection")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-003",
                    "HttpURLConnection Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "Validate destination URLs before requests."
            );
        }
    }

    private void detectRestTemplate(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("RestTemplate")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-004",
                    "RestTemplate Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "Review user-controlled URLs used by RestTemplate."
            );
        }
    }

    private void detectWebClient(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("WebClient")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-005",
                    "WebClient Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "Review URL validation before outbound requests."
            );
        }
    }

    private void detectOkHttp(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("OkHttpClient")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-006",
                    "OkHttp Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "Outbound requests should be restricted."
            );
        }
    }

    private void detectApacheHttpClient(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("HttpClient")
                || cu.toString().contains("CloseableHttpClient")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SSRF-007",
                    "Apache HttpClient Usage",
                    "SSRF",
                    "High",
                    "Medium",
                    "CWE-918",
                    "A10:2025",
                    "Validate and whitelist destinations."
            );
        }
    }

    private void detectOpenRedirect(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("sendRedirect(")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-SSRF-008",
                        "Potential Open Redirect",
                        "SSRF",
                        "Medium",
                        "Medium",
                        "CWE-601",
                        "A01:2025",
                        "Validate redirect targets."
                );
            }
        });
    }

    private void detectInternalAddresses(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("127.0.0.1")
                    || value.contains("localhost")
                    || value.contains("10.")
                    || value.contains("192.168.")
                    || value.contains("172.16.")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SSRF-009",
                        "Internal Network Address",
                        "SSRF",
                        "High",
                        "High",
                        "CWE-918",
                        "A10:2025",
                        "Internal address referenced in code."
                );
            }
        });
    }

    private void detectMetadataEndpoints(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("169.254.169.254")
                    || value.contains("metadata.google.internal")
                    || value.contains("latest/meta-data")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SSRF-010",
                        "Cloud Metadata Endpoint Access",
                        "SSRF",
                        "Critical",
                        "High",
                        "CWE-918",
                        "A10:2025",
                        "Potential access to cloud instance metadata service."
                );
            }
        });
    }
}