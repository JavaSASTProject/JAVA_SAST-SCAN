package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class APISecurityRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectWildcardCors(cu, file, findings);
        detectMissingAuthentication(cu, file, findings);
        detectMissingAuthorization(cu, file, findings);
        detectSensitiveDataExposure(cu, file, findings);
        detectRateLimiting(cu, file, findings);
        detectAdminEndpoints(cu, file, findings);
        detectSwaggerExposure(cu, file, findings);
        detectApiKeys(cu, file, findings);
        detectInputValidation(cu, file, findings);
    }

    private void detectWildcardCors(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(AnnotationExpr.class).forEach(a -> {

            if (a.toString().contains("@CrossOrigin")
                    && a.toString().contains("*")) {

                addFinding(
                        findings,
                        file,
                        a,
                        "JAVA-API-003",
                        "Wildcard CORS",
                        "API Security",
                        "High",
                        "High",
                        "CWE-942",
                        "API8:2023",
                        "API accessible from all origins."
                );
            }
        });
    }

    private void detectMissingAuthentication(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        boolean controller =
                source.contains("@RestController")
                || source.contains("@Controller");

        boolean auth =
                source.contains("@PreAuthorize")
                || source.contains("@RolesAllowed")
                || source.contains("@Secured");

        if (controller && !auth) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-API-001",
                    "Missing Authentication Control",
                    "API Security",
                    "High",
                    "Medium",
                    "CWE-306",
                    "API2:2023",
                    "Controller detected without authentication annotations."
            );
        }
    }

    private void detectMissingAuthorization(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("@RestController")
                && !source.contains("@RolesAllowed")
                && !source.contains("@PreAuthorize")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-API-002",
                    "Missing Authorization Control",
                    "API Security",
                    "High",
                    "Medium",
                    "CWE-862",
                    "API1:2023",
                    "Role-based access control not detected."
            );
        }
    }

    private void detectSensitiveDataExposure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class)
                .forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("password")
                    || value.contains("token")
                    || value.contains("secret")
                    || value.contains("ssn")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-API-004",
                        "Sensitive Data Exposure",
                        "API Security",
                        "Medium",
                        "High",
                        "CWE-200",
                        "API3:2023",
                        "Sensitive information may be returned through API."
                );
            }
        });
    }

    private void detectRateLimiting(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (!source.contains("ratelimit")
                && !source.contains("bucket4j")
                && !source.contains("resilience4j")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-API-005",
                    "Rate Limiting Not Detected",
                    "API Security",
                    "Medium",
                    "Low",
                    "CWE-770",
                    "API4:2023",
                    "Review API rate limiting controls."
            );
        }
    }

    private void detectAdminEndpoints(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class)
                .forEach(expr -> {

            String value =
                    expr.asString().toLowerCase();

            if (value.contains("/admin")
                    || value.contains("/administrator")
                    || value.contains("/manage")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-API-009",
                        "Administrative Endpoint",
                        "API Security",
                        "High",
                        "Medium",
                        "CWE-862",
                        "API1:2023",
                        "Administrative endpoint detected."
                );
            }
        });
    }

    private void detectSwaggerExposure(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (source.contains("swagger")
                || source.contains("openapi")
                || source.contains("/v3/api-docs")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-API-010",
                    "Swagger/OpenAPI Exposure",
                    "API Security",
                    "Medium",
                    "Medium",
                    "CWE-200",
                    "API9:2023",
                    "API documentation endpoint detected."
            );
        }
    }

    private void detectApiKeys(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (source.contains("apikey")
                || source.contains("api_key")
                || source.contains("x-api-key")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-API-007",
                    "API Key Detected",
                    "API Security",
                    "High",
                    "Medium",
                    "CWE-798",
                    "API2:2023",
                    "Potential hardcoded API key."
            );
        }
    }

    private void detectInputValidation(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString();

        if (source.contains("@RequestParam")
                || source.contains("@PathVariable")) {

            if (!source.contains("@Valid")) {

                addFinding(
                        findings,
                        file,
                        cu,
                        "JAVA-API-008",
                        "Missing Input Validation",
                        "API Security",
                        "Medium",
                        "Medium",
                        "CWE-20",
                        "API8:2023",
                        "Input validation annotation not detected."
                );
            }
        }
    }
}