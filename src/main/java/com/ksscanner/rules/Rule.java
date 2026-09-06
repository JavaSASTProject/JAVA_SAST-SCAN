package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public interface Rule {

    List<Finding> analyze(
            CompilationUnit cu,
            String fileName,
            Path filePath
    );
}