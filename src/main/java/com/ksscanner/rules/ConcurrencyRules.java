package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.SynchronizedStmt;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class ConcurrencyRules extends BaseRuleGroup {

    @Override
    protected void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectThreadSleep(cu, file, findings);
        detectThreadStop(cu, file, findings);
        detectThreadSuspend(cu, file, findings);
        detectThreadResume(cu, file, findings);
        detectSynchronizationOnString(cu, file, findings);
        detectUnsafeCollections(cu, file, findings);
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
                        "JAVA-CON-001",
                        "Concurrency",
                        "Low",
                        "Medium",
                        "CWE-667",
                        "A04:2025",
                        "Thread.sleep may cause timing issues.",
                        "Avoid Thread.sleep for synchronization."
                );
            }
        });
    }

    private void detectThreadStop(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("stop".equals(call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-CON-006",
                        "Concurrency",
                        "High",
                        "High",
                        "CWE-570",
                        "A04:2025",
                        "Thread.stop is deprecated and unsafe.",
                        "Use interruption or cooperative thread termination."
                );
            }
        });
    }

    private void detectThreadSuspend(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("suspend".equals(call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-CON-007",
                        "Concurrency",
                        "High",
                        "High",
                        "CWE-570",
                        "A04:2025",
                        "Thread.suspend may cause deadlocks.",
                        "Avoid Thread.suspend and use modern concurrency controls."
                );
            }
        });
    }

    private void detectThreadResume(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("resume".equals(call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-CON-008",
                        "Concurrency",
                        "High",
                        "High",
                        "CWE-570",
                        "A04:2025",
                        "Thread.resume is deprecated and unsafe.",
                        "Use proper thread coordination mechanisms."
                );
            }
        });
    }

    private void detectSynchronizationOnString(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(SynchronizedStmt.class).forEach(sync -> {

            if (sync.getExpression() instanceof StringLiteralExpr) {

                addFinding(
                        findings,
                        file,
                        sync,
                        "JAVA-CON-002",
                        "Concurrency",
                        "Medium",
                        "High",
                        "CWE-662",
                        "A04:2025",
                        "Avoid synchronizing on String literals.",
                        "Use dedicated lock objects."
                );
            }
        });
    }

    private void detectUnsafeCollections(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(FieldDeclaration.class).forEach(field -> {

            String text = field.toString();

            if (text.contains("ArrayList")
                    || text.contains("HashMap")
                    || text.contains("HashSet")) {

                addFinding(
                        findings,
                        file,
                        field,
                        "JAVA-CON-004",
                        "Concurrency",
                        "Medium",
                        "Medium",
                        "CWE-362",
                        "A04:2025",
                        "Potential shared mutable collection detected.",
                        "Review thread safety and consider concurrent collections."
                );
            }
        });
    }
}