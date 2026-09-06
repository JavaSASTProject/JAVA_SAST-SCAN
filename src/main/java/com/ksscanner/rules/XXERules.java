package com.ksscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.ksscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

public class XXERules extends BaseRuleGroup {

    @Override
    public void scan(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        detectDocumentBuilderFactory(cu, file, findings);
        detectSaxParserFactory(cu, file, findings);
        detectXmlInputFactory(cu, file, findings);
        detectTransformerFactory(cu, file, findings);
        detectExternalEntities(cu, file, findings);
        detectDtdProcessing(cu, file, findings);
        detectXmlReader(cu, file, findings);
        detectSaxReader(cu, file, findings);
        detectDom4j(cu, file, findings);
    }

    private void detectDocumentBuilderFactory(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains(
                "DocumentBuilderFactory")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-001",
                    "DocumentBuilderFactory Usage",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "Review XML parser configuration to ensure XXE protection."
            );
        }
    }

    private void detectSaxParserFactory(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains(
                "SAXParserFactory")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-002",
                    "SAXParserFactory Usage",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "SAX parser detected. Verify XXE protection."
            );
        }
    }

    private void detectXmlInputFactory(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains(
                "XMLInputFactory")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-003",
                    "XMLInputFactory Usage",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "StAX parser detected. Verify external entities are disabled."
            );
        }
    }

    private void detectTransformerFactory(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains(
                "TransformerFactory")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-004",
                    "TransformerFactory Usage",
                    "XML Security",
                    "Medium",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "Verify secure XML transformation settings."
            );
        }
    }

    private void detectExternalEntities(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("external-general-entities")
                || source.contains("external-parameter-entities")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-005",
                    "External Entity Processing Enabled",
                    "XML Security",
                    "High",
                    "High",
                    "CWE-611",
                    "A05:2025",
                    "External entities appear enabled."
            );
        }
    }

    private void detectDtdProcessing(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        String source = cu.toString();

        if (source.contains("DOCTYPE")
                || source.contains("disallow-doctype-decl")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-006",
                    "DTD Processing Detected",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "DTD processing should be reviewed."
            );
        }
    }

    private void detectXmlReader(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("XMLReader")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-007",
                    "XMLReader Usage",
                    "XML Security",
                    "Medium",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "XMLReader detected."
            );
        }
    }

    private void detectSaxReader(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("SAXReader")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-008",
                    "SAXReader Usage",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "DOM4J SAXReader detected."
            );
        }
    }

    private void detectDom4j(
            CompilationUnit cu,
            Path file,
            List<Finding> findings) {

        if (cu.toString().contains("dom4j")) {

            addFinding(
                    findings,
                    file,
                    cu,
                    "JAVA-XXE-009",
                    "DOM4J XML Parsing",
                    "XML Security",
                    "High",
                    "Medium",
                    "CWE-611",
                    "A05:2025",
                    "Review DOM4J parser configuration."
            );
        }
    }
}