package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class DeserializationRules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectObjectInputStream(cu, file, findings);
        detectXMLDecoder(cu, file, findings);
        detectReadObject(cu, file, findings);
        detectJacksonDefaultTyping(cu, file, findings);
        detectFastjsonAutoType(cu, file, findings);
        detectSnakeYaml(cu, file, findings);
        detectXStream(cu, file, findings);
        detectSerializable(cu, file, findings);
        detectExternalizable(cu, file, findings);
    }

    private void detectObjectInputStream(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {

            if ("ObjectInputStream".equals(
                    expr.getType().asString())) {

                addFinding(
                        findings,
                        file,
                        expr,
                        "JAVA-DESER-001",
                        "ObjectInputStream Usage",
                        "Deserialization",
                        "High",
                        "High",
                        "CWE-502",
                        "A08:2025",
                        "Potential unsafe Java deserialization."
                );
            }
        });
    }

    private void detectXMLDecoder(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("XMLDecoder")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-DESER-002",
                    "XMLDecoder Usage",
                    "Deserialization",
                    "High",
                    "High",
                    "CWE-502",
                    "A08:2025",
                    "XMLDecoder may deserialize untrusted data."
            );
        }
    }

    private void detectReadObject(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(MethodCallExpr.class).forEach(call -> {

            if ("readObject".equals(
                    call.getNameAsString())) {

                addFinding(
                        findings,
                        file,
                        call,
                        "JAVA-DESER-003",
                        "readObject Invocation",
                        "Deserialization",
                        "High",
                        "High",
                        "CWE-502",
                        "A08:2025",
                        "Object deserialization detected."
                );
            }
        });
    }

    private void detectJacksonDefaultTyping(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("enableDefaultTyping")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-DESER-004",
                    "Jackson Default Typing Enabled",
                    "Deserialization",
                    "High",
                    "High",
                    "CWE-502",
                    "A08:2025",
                    "Unsafe polymorphic deserialization."
            );
        }
    }

    private void detectFastjsonAutoType(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("setAutoTypeSupport")
                || source.contains("autoType")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-DESER-005",
                    "Fastjson AutoType Enabled",
                    "Deserialization",
                    "High",
                    "High",
                    "CWE-502",
                    "A08:2025",
                    "Fastjson AutoType can enable gadget chains."
            );
        }
    }

    private void detectSnakeYaml(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("Yaml.load(")
                || source.contains("new Yaml(")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-DESER-006",
                    "SnakeYAML Unsafe Load",
                    "Deserialization",
                    "High",
                    "Medium",
                    "CWE-502",
                    "A08:2025",
                    "Unsafe YAML deserialization."
            );
        }
    }

    private void detectXStream(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("XStream")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-DESER-007",
                    "XStream Usage",
                    "Deserialization",
                    "High",
                    "Medium",
                    "CWE-502",
                    "A08:2025",
                    "Review XStream security configuration."
            );
        }
    }

    private void detectSerializable(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ClassOrInterfaceDeclaration.class)
                .forEach(clazz -> {

            if (clazz.getImplementedTypes()
                    .stream()
                    .anyMatch(t -> t.getNameAsString()
                            .equals("Serializable"))) {

                addFinding(
                        findings,
                        file,
                        clazz,
                        "JAVA-DESER-008",
                        "Serializable Implementation",
                        "Deserialization",
                        "Medium",
                        "Medium",
                        "CWE-502",
                        "A08:2025",
                        "Review serialization security controls."
                );
            }
        });
    }

    private void detectExternalizable(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        cu.findAll(ClassOrInterfaceDeclaration.class)
                .forEach(clazz -> {

            if (clazz.getImplementedTypes()
                    .stream()
                    .anyMatch(t -> t.getNameAsString()
                            .equals("Externalizable"))) {

                addFinding(
                        findings,
                        file,
                        clazz,
                        "JAVA-DESER-009",
                        "Externalizable Implementation",
                        "Deserialization",
                        "Medium",
                        "Medium",
                        "CWE-502",
                        "A08:2025",
                        "Review custom deserialization logic."
                );
            }
        });
    }
}