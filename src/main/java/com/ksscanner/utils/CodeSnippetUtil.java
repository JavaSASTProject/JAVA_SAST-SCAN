package com.ksscanner.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CodeSnippetUtil {

    public static String getSnippet(Path filePath,
                                    int targetLine,
                                    int contextLines) {

        try {

            List<String> lines =
                    Files.readAllLines(filePath);

            int start =
                    Math.max(1,
                            targetLine - contextLines);

            int end =
                    Math.min(lines.size(),
                            targetLine + contextLines);

            StringBuilder snippet =
                    new StringBuilder();

            for (int i = start; i <= end; i++) {

                snippet.append(i)
                        .append(": ")
                        .append(lines.get(i - 1))
                        .append("\n");
            }

            return snippet.toString();

        } catch (Exception e) {

            return "Snippet unavailable";
        }
    }
}