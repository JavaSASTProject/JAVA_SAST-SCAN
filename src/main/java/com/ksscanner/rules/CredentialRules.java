package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class CredentialRules extends BaseRuleGroup {

    @Override
    protected void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        // Credential detection rules will be added here
    }
}