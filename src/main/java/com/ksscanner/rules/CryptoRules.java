package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class CryptoRules extends BaseRuleGroup {

    @Override
    protected void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectMd5(cu, file, findings);
        detectSha1(cu, file, findings);
        detectDes(cu, file, findings);
        detectTripleDes(cu, file, findings);
        detectAesEcb(cu, file, findings);
        detectWeakRandom(cu, file, findings);
        detectHardcodedKey(cu, file, findings);
        detectWeakRsa(cu, file, findings);
    }

    private void detectMd5(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("MD5")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-CRYPTO-001",
                        "Weak Hash Algorithm MD5",
                        "Cryptography",
                        "High",
                        "High",
                        "CWE-327",
                        "A02:2025",
                        "MD5 is cryptographically broken."
                );
            }
        });
    }

    private void detectSha1(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("SHA-1")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-CRYPTO-002",
                        "Weak Hash Algorithm SHA-1",
                        "Cryptography",
                        "High",
                        "High",
                        "CWE-327",
                        "A02:2025",
                        "SHA-1 is deprecated."
                );
            }
        });
    }

    private void detectDes(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("DES")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CRYPTO-003",
                    "DES Usage",
                    "Cryptography",
                    "High",
                    "Medium",
                    "CWE-327",
                    "A02:2025",
                    "DES is insecure."
            );
        }
    }

    private void detectTripleDes(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("DESede")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CRYPTO-004",
                    "3DES Usage",
                    "Cryptography",
                    "Medium",
                    "Medium",
                    "CWE-327",
                    "A02:2025",
                    "3DES is deprecated."
            );
        }
    }

    private void detectAesEcb(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("AES/ECB")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CRYPTO-005",
                    "AES ECB Mode",
                    "Cryptography",
                    "High",
                    "High",
                    "CWE-327",
                    "A02:2025",
                    "ECB mode should not be used."
            );
        }
    }

    private void detectWeakRandom(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class)
                .forEach(expr -> {

            if ("Random".equals(expr.getType().asString())) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-CRYPTO-006",
                        "Weak Random Generator",
                        "Cryptography",
                        "Medium",
                        "High",
                        "CWE-338",
                        "A02:2025",
                        "Use SecureRandom instead."
                );
            }
        });
    }

    private void detectHardcodedKey(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString().toLowerCase();

        if (source.contains("secretkeyspec")
                || source.contains("privatekey")
                || source.contains("secretkey")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CRYPTO-007",
                    "Hardcoded Cryptographic Key",
                    "Cryptography",
                    "High",
                    "Medium",
                    "CWE-321",
                    "A02:2025",
                    "Potential hardcoded cryptographic key."
            );
        }
    }

    private void detectWeakRsa(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("1024")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CRYPTO-008",
                    "Weak RSA Key Size",
                    "Cryptography",
                    "Medium",
                    "Medium",
                    "CWE-326",
                    "A02:2025",
                    "RSA keys below 2048 bits are not recommended."
            );
        }
    }
}