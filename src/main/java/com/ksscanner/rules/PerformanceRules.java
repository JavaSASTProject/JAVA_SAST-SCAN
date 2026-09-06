package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class PerformanceRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectStringConcatenationInLoop(cu, file, findings);
        detectThreadSleep(cu, file, findings);
        detectSystemGc(cu, file, findings);
        detectNestedLoops(cu, file, findings);
        detectObjectCreationInLoop(cu, file, findings);
        detectArrayListContainsInLoop(cu, file, findings);
        detectRepeatedDatabaseCalls(cu, file, findings);
        detectRepeatedFileAccess(cu, file, findings);
    }

    private void detectStringConcatenationInLoop(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ForStmt.class).forEach(loop -> {

            String code = loop.toString();

            if (code.contains("+=")
                    && code.contains("String")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-001",
                        "String Concatenation Inside Loop",
                        "Performance",
                        "Medium",
                        "Medium",
                        "CWE-400",
                        "N/A",
                        "Use StringBuilder instead of String concatenation inside loops."
                );
            }
        });
    }

    private void detectThreadSleep(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("sleep".equals(call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-PERF-002",
                        "Thread.sleep Usage",
                        "Performance",
                        "Low",
                        "High",
                        "CWE-400",
                        "N/A",
                        "Thread.sleep may cause unnecessary delays."
                );
            }
        });
    }

    private void detectSystemGc(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            String text = call.toString();

            if (text.contains("System.gc")) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-PERF-003",
                        "System.gc Invocation",
                        "Performance",
                        "Low",
                        "High",
                        "CWE-400",
                        "N/A",
                        "Explicit garbage collection may impact application performance."
                );
            }
        });
    }

    private void detectNestedLoops(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ForStmt.class).forEach(loop -> {

            String code = loop.toString();

            if (code.contains("for(")
                    && code.lastIndexOf("for(")
                    != code.indexOf("for(")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-004",
                        "Nested Loop Detected",
                        "Performance",
                        "Medium",
                        "Medium",
                        "CWE-407",
                        "N/A",
                        "Nested loops may result in poor scalability."
                );
            }
        });
    }

    private void detectObjectCreationInLoop(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ForStmt.class).forEach(loop -> {

            if (loop.toString().contains("new ")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-005",
                        "Object Creation Inside Loop",
                        "Performance",
                        "Medium",
                        "Medium",
                        "CWE-400",
                        "N/A",
                        "Avoid creating objects repeatedly inside loops."
                );
            }
        });

        cu.findAll(WhileStmt.class).forEach(loop -> {

            if (loop.toString().contains("new ")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-005",
                        "Object Creation Inside Loop",
                        "Performance",
                        "Medium",
                        "Medium",
                        "CWE-400",
                        "N/A",
                        "Avoid creating objects repeatedly inside loops."
                );
            }
        });
    }

    private void detectArrayListContainsInLoop(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ForStmt.class).forEach(loop -> {

            if (loop.toString().contains(".contains(")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-006",
                        "Collection Search Inside Loop",
                        "Performance",
                        "Medium",
                        "Medium",
                        "CWE-407",
                        "N/A",
                        "Consider HashSet for frequent lookups."
                );
            }
        });
    }

    private void detectRepeatedDatabaseCalls(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ForStmt.class).forEach(loop -> {

            String code = loop.toString().toLowerCase();

            if (code.contains("executequery")
                    || code.contains("executeselect")
                    || code.contains("findbyid")
                    || code.contains("repository.")) {

                addFinding(
                        findings,
                        file,
                        loop,
                        "JAVA-PERF-007",
                        "Database Call Inside Loop",
                        "Performance",
                        "High",
                        "Medium",
                        "CWE-400",
                        "N/A",
                        "Database operations inside loops may cause N+1 query issues."
                );
            }
        });
    }

    private void detectRepeatedFileAccess(
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
                        "JAVA-PERF-008",
                        "File Access Operation",
                        "Performance",
                        "Low",
                        "Medium",
                        "CWE-400",
                        "N/A",
                        "Review repeated file access operations."
                );
            }
        });
    }
}