package com.ksscanner.sca;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PomParser {

    public List<Dependency> parse(File pomFile)
            throws Exception {

        List<Dependency> dependencies =
                new ArrayList<>();

        Document document =
                DocumentBuilderFactory
                        .newInstance()
                        .newDocumentBuilder()
                        .parse(pomFile);

        document.getDocumentElement().normalize();

        NodeList dependencyNodes =
                document.getElementsByTagName(
                        "dependency");

        for (int i = 0;
             i < dependencyNodes.getLength();
             i++) {

            Element dependency =
                    (Element)
                            dependencyNodes.item(i);

            String groupId =
                    getTagValue(
                            dependency,
                            "groupId");

            String artifactId =
                    getTagValue(
                            dependency,
                            "artifactId");

            String version =
                    getTagValue(
                            dependency,
                            "version");

            if (groupId == null) {
                groupId = "";
            }

            if (artifactId == null) {
                artifactId = "";
            }

            if (version == null) {
                version = "";
            }

            dependencies.add(
                    new Dependency(
                            groupId,
                            artifactId,
                            version));
        }

        return dependencies;
    }

    private String getTagValue(
            Element element,
            String tagName) {

        NodeList nodes =
                element.getElementsByTagName(
                        tagName);

        if (nodes.getLength() == 0) {
            return "";
        }

        return nodes
                .item(0)
                .getTextContent()
                .trim();
    }
}