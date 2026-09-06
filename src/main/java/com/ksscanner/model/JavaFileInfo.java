package com.ksscanner.model;

import java.util.ArrayList;
import java.util.List;

public class JavaFileInfo {

    private String fileName;
    private String packageName;

    private List<String> imports = new ArrayList<>();
    private List<String> classes = new ArrayList<>();
    private List<String> methods = new ArrayList<>();
    private List<String> fields = new ArrayList<>();

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public List<String> getImports() {
        return imports;
    }

    public List<String> getClasses() {
        return classes;
    }

    public List<String> getMethods() {
        return methods;
    }

    public List<String> getFields() {
        return fields;
    }
}