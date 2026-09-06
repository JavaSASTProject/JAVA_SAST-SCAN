package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.comments.Comment;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.IfStmt;
import com.ksscanner.model.Finding;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.body.ConstructorDeclaration;

import java.nio.file.Path;
import com.github.javaparser.ast.body.VariableDeclarator;
import java.util.List;

public class CodeQualityRules extends BaseRuleGroup {

    @Override
public void scan(CompilationUnit cu,
                 Path file,
                 List<Finding> findings) {

    detectEmptyCatch(cu, file, findings);
    detectGenericExceptionCatch(cu, file, findings);
    detectTodoComments(cu, file, findings);
    detectDeadCode(cu, file, findings);
    detectLongMethods(cu, file, findings);
    detectLargeClasses(cu, file, findings);
    detectSystemOutPrintln(cu, file, findings);

    // New Rules
    detectExcessiveParameters(cu, file, findings);
    detectEmptyMethods(cu, file, findings);
    
}

    private void detectEmptyCatch(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            if (catchClause.getBody().getStatements().isEmpty()) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-CQ-001",
                        "Empty Catch Block",
                        "Code Quality",
                        "Medium",
                        "High",
                        "CWE-390",
                        "A09:2025",
                        "Exception is silently ignored."
                );
            }
        });
    }private void detectExcessiveParameters(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(MethodDeclaration.class).forEach(method -> {

        if (method.getParameters().size() > 5) {

            addFinding(
                    findings,
                    file,
                    method,
                    "JAVA-CQ-008",
                    "Excessive Parameters",
                    "Code Quality",
                    "Low",
                    "High",
                    "CWE-710",
                    "A09:2025",
                    "Method has more than 5 parameters."
            );
        }
    });
}


private void detectUnusedVariables(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(VariableDeclarator.class)
            .forEach(var -> {

                String name = var.getNameAsString();

                long references =
                        cu.findAll(com.github.javaparser.ast.expr.NameExpr.class)
                                .stream()
                                .filter(n -> n.getNameAsString().equals(name))
                                .count();

                if (references <= 1) {

                    addFinding(
                            findings,
                            file,
                            var,
                            "JAVA-CQ-018",
                            "Unused Variable",
                            "Code Quality",
                            "Low",
                            "Medium",
                            "CWE-563",
                            "A09:2025",
                            "Variable declared but never used."
                    );
                }
            });
}
private void detectEmptyMethods(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(MethodDeclaration.class).forEach(method -> {

        if (method.getBody().isPresent()
                && method.getBody().get()
                .getStatements().isEmpty()) {

            addFinding(
                    findings,
                    file,
                    method,
                    "JAVA-CQ-009",
                    "Empty Method",
                    "Code Quality",
                    "Low",
                    "High",
                    "CWE-398",
                    "A09:2025",
                    "Method contains no implementation."
            );
        }
    });
}
private void detectEmptyFinallyBlocks(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(TryStmt.class).forEach(tryStmt -> {

        if (tryStmt.getFinallyBlock().isPresent()
                && tryStmt.getFinallyBlock().get()
                .getStatements().isEmpty()) {

            addFinding(
                    findings,
                    file,
                    tryStmt,
                    "JAVA-CQ-012",
                    "Empty Finally Block",
                    "Code Quality",
                    "Low",
                    "Medium",
                    "CWE-398",
                    "A09:2025",
                    "Finally block is empty."
            );
        }
    });
}
private void detectEmptyConstructors(
        CompilationUnit cu,
        Path file,
        List<Finding> findings) {

    cu.findAll(ConstructorDeclaration.class)
            .forEach(constructor -> {

                if (constructor.getBody()
                        .getStatements()
                        .isEmpty()) {

                    addFinding(
                            findings,
                            file,
                            constructor,
                            "JAVA-CQ-015",
                            "Empty Constructor",
                            "Code Quality",
                            "Low",
                            "High",
                            "CWE-398",
                            "A09:2025",
                            "Constructor contains no logic."
                    );
                }
            });
}

    private void detectGenericExceptionCatch(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(CatchClause.class).forEach(catchClause -> {

            String type =
                    catchClause.getParameter()
                            .getType()
                            .asString();

            if ("Exception".equals(type)
                    || "Throwable".equals(type)) {

                addFinding(
                        findings,
                        file,
                        catchClause,
                        "JAVA-CQ-002",
                        "Generic Exception Catch",
                        "Code Quality",
                        "Low",
                        "High",
                        "CWE-396",
                        "A09:2025",
                        "Avoid catching generic Exception or Throwable."
                );
            }
        });
    }

    private void detectTodoComments(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        for (Comment comment : cu.getAllContainedComments()) {

            String text =
                    comment.getContent().toLowerCase();

            if (text.contains("todo")
                    || text.contains("fixme")
                    || text.contains("hack")) {

                addFinding(
                        findings,
                        file,
                        comment,
                        "JAVA-CQ-003",
                        "TODO/FIXME Comment",
                        "Code Quality",
                        "Low",
                        "Medium",
                        "CWE-546",
                        "A09:2025",
                        "Comment indicates unfinished or temporary code."
                );
            }
        }
    }

    private void detectDeadCode(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(IfStmt.class).forEach(ifStmt -> {

            if (ifStmt.getCondition() instanceof BooleanLiteralExpr) {

                BooleanLiteralExpr expr =
                        (BooleanLiteralExpr) ifStmt.getCondition();

                if (!expr.getValue()) {

                    addFinding(
                            findings,
                            file,
                            ifStmt,
                            "JAVA-CQ-004",
                            "Dead Code",
                            "Code Quality",
                            "Low",
                            "Medium",
                            "CWE-561",
                            "A09:2025",
                            "Code block can never execute."
                    );
                }
            }
        });
    }

    private void detectLongMethods(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodDeclaration.class).forEach(method -> {

            if (!method.getRange().isPresent()) {
                return;
            }

            int lines =
                    method.getRange().get().end.line
                            - method.getRange().get().begin.line;

            if (lines > 100) {

                addFinding(
                        findings,
                        file,
                        method,
                        "JAVA-CQ-005",
                        "Long Method",
                        "Code Quality",
                        "Low",
                        "Medium",
                        "CWE-710",
                        "A09:2025",
                        "Method exceeds 100 lines and should be refactored."
                );
            }
        });
    }

    private void detectLargeClasses(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (!cu.getRange().isPresent()) {
            return;
        }

        int lines =
                cu.getRange().get().end.line
                        - cu.getRange().get().begin.line;

        if (lines > 1000) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-CQ-006",
                    "Large Class",
                    "Code Quality",
                    "Low",
                    "Medium",
                    "CWE-710",
                    "A09:2025",
                    "Class exceeds 1000 lines and should be split into smaller components."
            );
        }
    }

    private void detectSystemOutPrintln(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(com.github.javaparser.ast.expr.MethodCallExpr.class)
                .forEach(call -> {

                    String methodName = call.getNameAsString();

                    if (!"println".equals(methodName)) {
                        return;
                    }

                    if (!call.getScope().isPresent()) {
                        return;
                    }

                    String scope =
                            call.getScope().get().toString();

                    if ("System.out".equals(scope)
                            || "System.err".equals(scope)) {

                        addFinding(
                                findings,
                                file,
                                call,
                                "JAVA-CQ-007",
                                "System.out.println Usage",
                                "Code Quality",
                                "Low",
                                "High",
                                "CWE-489",
                                "A09:2025",
                                "Use a logging framework instead of System.out.println."
                        );
                    }
                });
    }
}