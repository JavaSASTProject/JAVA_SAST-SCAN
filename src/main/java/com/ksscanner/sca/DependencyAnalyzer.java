package com.ksscanner.sca;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DependencyAnalyzer {

    public List<Dependency> analyze(
            Path projectPath)
            throws Exception {

        List<Dependency> dependencies =
                new ArrayList<>();

        Path pomFile =
                projectPath.resolve("pom.xml");

        if (!Files.exists(pomFile)) {

            return dependencies;
        }

        PomParser parser =
                new PomParser();

        dependencies.addAll(
                parser.parse(
                        pomFile.toFile()));

        return dependencies;
    }
}