package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public abstract class BaseRuleGroup implements Rule {

    @Override
    public List<Finding> analyze(
            CompilationUnit cu,
            String fileName,
            Path filePath) {

        List<Finding> findings = new ArrayList<>();

        scan(cu, filePath, findings);

        return findings;
    }

    protected abstract void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings);

    protected void addFinding(
        List<Finding> findings,
        Path file,
        Node node,
        String ruleId,
        String title,
        String category,
        String severity,
        String confidence,
        String cwe,
        String owasp,
        String message) {

    int line = 0;
    int column = 0;

    if (node != null && node.getRange().isPresent()) {
        line = node.getRange().get().begin.line;
        column = node.getRange().get().begin.column;
    }

    String snippet = "";

    if (node != null) {
        snippet = node.toString();
    }

    Finding finding = new Finding(
            ruleId,
            category,          // Access Control
            severity,          // Medium
            confidence,        // High
            cwe,               // CWE-269
            owasp,             // A01:2025
            title,             // Hardcoded Administrative Role
            message,           // Hardcoded privileged role detected.
            file.toString(),
            line,
            column,
            snippet,
            "",
            ""
    );

    findings.add(finding);
}
}