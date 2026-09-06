package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class FileHandlingRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectPathTraversal(cu, file, findings);
        detectFileRead(cu, file, findings);
        detectFileWrite(cu, file, findings);
        detectZipSlip(cu, file, findings);
        detectUnsafeTempFile(cu, file, findings);
        detectFileUpload(cu, file, findings);
        detectUserControlledPath(cu, file, findings);
    }

    private void detectPathTraversal(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(StringLiteralExpr.class).forEach(expr -> {

            String value = expr.asString();

            if (value.contains("../")
                    || value.contains("..\\")
                    || value.contains("%2e%2e")) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-FILE-001",
                        "Path Traversal",
                        "File Handling",
                        "High",
                        "High",
                        "CWE-22",
                        "A01:2025",
                        "Directory traversal sequence detected."
                );
            }
        });
    }

    private void detectFileRead(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            String type = expr.getType().asString();

            if ("FileInputStream".equals(type)
                    || "FileReader".equals(type)
                    || "BufferedReader".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-FILE-002",
                        "File Read Operation",
                        "File Handling",
                        "Medium",
                        "Medium",
                        "CWE-73",
                        "A01:2025",
                        "Review file path validation before reading files."
                );
            }
        });
    }

    private void detectFileWrite(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            String type = expr.getType().asString();

            if ("FileWriter".equals(type)
                    || "FileOutputStream".equals(type)
                    || "PrintWriter".equals(type)) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-FILE-003",
                        "File Write Operation",
                        "File Handling",
                        "Medium",
                        "Medium",
                        "CWE-73",
                        "A01:2025",
                        "Review file path validation before writing files."
                );
            }
        });
    }

    private void detectZipSlip(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("ZipEntry")
                || source.contains("getNextEntry()")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-FILE-004",
                    "Potential Zip Slip",
                    "File Handling",
                    "High",
                    "Medium",
                    "CWE-22",
                    "A01:2025",
                    "Validate ZipEntry paths before extraction."
            );
        }
    }

    private void detectUnsafeTempFile(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if (call.toString().contains("createTempFile")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-FILE-005",
                        "Temporary File Usage",
                        "File Handling",
                        "Medium",
                        "Medium",
                        "CWE-377",
                        "A05:2025",
                        "Review permissions and cleanup of temporary files."
                );
            }
        });
    }

    private void detectFileUpload(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source =
                cu.toString().toLowerCase();

        if (source.contains("multipartfile")
                || source.contains("getoriginalfilename")
                || source.contains("fileupload")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-FILE-006",
                    "File Upload Functionality",
                    "File Handling",
                    "High",
                    "Medium",
                    "CWE-434",
                    "A05:2025",
                    "Validate file type, size and content."
            );
        }
    }

    private void detectUserControlledPath(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(VariableDeclarator.class).forEach(var -> {

            String name =
                    var.getNameAsString().toLowerCase();

            if (name.contains("filepath")
                    || name.contains("filename")
                    || name.contains("path")) {

                addFinding(
                        findings,
                        file,
                        var,
                        "JAVA-FILE-009",
                        "User Controlled File Path",
                        "File Handling",
                        "High",
                        "Medium",
                        "CWE-22",
                        "A01:2025",
                        "Validate and canonicalize file paths."
                );
            }
        });
    }
}