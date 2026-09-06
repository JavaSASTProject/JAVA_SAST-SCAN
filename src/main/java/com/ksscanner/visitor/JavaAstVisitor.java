package com.ksscanner.visitor;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

public class JavaAstVisitor extends VoidVisitorAdapter<Void> {

    private static final boolean DEBUG = false;

    @Override
    public void visit(ClassOrInterfaceDeclaration n, Void arg) {

        super.visit(n, arg);

        if (DEBUG) {
            System.out.println("Class  : " + n.getNameAsString());
        }
    }

    @Override
    public void visit(MethodDeclaration n, Void arg) {

        super.visit(n, arg);

        if (DEBUG) {
            System.out.println("Method : " + n.getNameAsString());
        }
    }

    @Override
    public void visit(FieldDeclaration n, Void arg) {

        super.visit(n, arg);

        if (DEBUG) {

            n.getVariables().forEach(variable ->
                    System.out.println(
                            "Field  : "
                                    + variable.getNameAsString()));
        }
    }
}