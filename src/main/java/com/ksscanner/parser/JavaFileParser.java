package com.ksscanner.parser;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;

import com.ksscanner.model.JavaFileInfo;

import java.io.File;
import java.io.IOException;

public class JavaFileParser {

    public JavaFileInfo parse(File file) throws IOException {

        CompilationUnit cu = StaticJavaParser.parse(file);

        JavaFileInfo info = new JavaFileInfo();

        info.setFileName(file.getName());

        info.setPackageName(
                cu.getPackageDeclaration()
                  .map(p -> p.getNameAsString())
                  .orElse("(default)")
        );

        cu.getImports().forEach(i ->
                info.getImports().add(i.getNameAsString()));

        cu.findAll(ClassOrInterfaceDeclaration.class)
                .forEach(c ->
                        info.getClasses().add(c.getNameAsString()));

        cu.findAll(MethodDeclaration.class)
                .forEach(m ->
                        info.getMethods().add(m.getNameAsString()));

        cu.findAll(FieldDeclaration.class)
                .forEach(f ->
                        f.getVariables().forEach(v ->
                                info.getFields().add(v.getNameAsString())
                        ));

        return info;
    }
    public CompilationUnit parseAst(File file) throws IOException {
    return StaticJavaParser.parse(file);
}
}