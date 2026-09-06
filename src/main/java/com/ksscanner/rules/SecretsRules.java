package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

public class SecretsRules extends BaseRuleGroup {

    private static final Pattern AWS_ACCESS_KEY =
            Pattern.compile("AKIA[0-9A-Z]{16}");

    private static final Pattern AWS_SECRET_KEY =
            Pattern.compile("[A-Za-z0-9/+=]{40}");

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectAwsAccessKey(cu, file, findings);
        detectAwsSecretKey(cu, file, findings);
        detectJwtSecret(cu, file, findings);
        detectApiKeys(cu, file, findings);
        detectBearerTokens(cu, file, findings);
        detectPrivateKeys(cu, file, findings);
        detectOauthSecrets(cu, file, findings);
        detectGcpKeys(cu, file, findings);
        detectAzureKeys(cu, file, findings);
    }

    private void detectAwsAccessKey(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            if (AWS_ACCESS_KEY.matcher(
                    expr.asString()).find()) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SECRET-001",
                        "AWS Access Key",
                        "Secrets",
                        "Critical",
                        "High",
                        "CWE-798",
                        "A07:2025",
                        "AWS access key detected."
                );
            }
        });
    }

    private void detectAwsSecretKey(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.length() == 40
                    && AWS_SECRET_KEY.matcher(value).matches()) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SECRET-002",
                        "AWS Secret Key",
                        "Secrets",
                        "Critical",
                        "Medium",
                        "CWE-798",
                        "A07:2025",
                        "Potential AWS secret key detected."
                );
            }
        });
    }

    private void detectJwtSecret(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("jwt.secret")
                || source.contains("signingkey")
                || source.contains("jwtsecret")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-005",
                    "JWT Secret",
                    "Secrets",
                    "High",
                    "High",
                    "CWE-798",
                    "A07:2025",
                    "Hardcoded JWT secret detected."
            );
        }
    }

    private void detectApiKeys(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("apikey")
                || source.contains("api_key")
                || source.contains("x-api-key")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-006",
                    "API Key",
                    "Secrets",
                    "High",
                    "Medium",
                    "CWE-798",
                    "A07:2025",
                    "Potential hardcoded API key."
            );
        }
    }

    private void detectBearerTokens(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            if (expr.asString().startsWith("Bearer ")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-SECRET-007",
                        "Bearer Token",
                        "Secrets",
                        "High",
                        "High",
                        "CWE-798",
                        "A07:2025",
                        "Hardcoded bearer token detected."
                );
            }
        });
    }

    private void detectPrivateKeys(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("BEGIN PRIVATE KEY")
                || source.contains("BEGIN RSA PRIVATE KEY")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-008",
                    "Private Key",
                    "Secrets",
                    "Critical",
                    "High",
                    "CWE-321",
                    "A02:2025",
                    "Private key material detected."
            );
        }

        if (source.contains("BEGIN OPENSSH PRIVATE KEY")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-009",
                    "SSH Private Key",
                    "Secrets",
                    "Critical",
                    "High",
                    "CWE-321",
                    "A02:2025",
                    "SSH private key detected."
            );
        }
    }

    private void detectOauthSecrets(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("clientsecret")
                || source.contains("client_secret")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-010",
                    "OAuth Client Secret",
                    "Secrets",
                    "High",
                    "Medium",
                    "CWE-798",
                    "A07:2025",
                    "OAuth client secret detected."
            );
        }
    }

    private void detectGcpKeys(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("\"private_key_id\"")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-004",
                    "GCP Service Account Key",
                    "Secrets",
                    "Critical",
                    "High",
                    "CWE-798",
                    "A07:2025",
                    "Google Cloud service account key detected."
            );
        }
    }

    private void detectAzureKeys(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("accountkey=")
                || source.contains("azurekey")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-SECRET-003",
                    "Azure Access Key",
                    "Secrets",
                    "Critical",
                    "Medium",
                    "CWE-798",
                    "A07:2025",
                    "Azure storage/account key detected."
            );
        }
    }
}