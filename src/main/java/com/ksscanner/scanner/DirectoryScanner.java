package com.ksscanner.scanner;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class DirectoryScanner {

    public List<Path> scan(String projectPath) throws IOException {

        List<Path> javaFiles = new ArrayList<>();

        Files.walk(Paths.get(projectPath))
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".java"))
                .forEach(javaFiles::add);

        return javaFiles;
    }
}