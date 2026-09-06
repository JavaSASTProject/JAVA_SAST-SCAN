package com.ksscanner.sca;

public class Dependency {

    private final String groupId;
    private final String artifactId;
    private final String version;

    public Dependency(
            String groupId,
            String artifactId,
            String version) {

        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getVersion() {
        return version;
    }

    public String getPurl() {

    if (version == null || version.isEmpty()) {
        return String.format(
                "pkg:maven/%s/%s",
                groupId,
                artifactId
        );
    }

    return String.format(
            "pkg:maven/%s/%s@%s",
            groupId,
            artifactId,
            version
    );
}

    @Override
    public String toString() {

        return groupId
                + ":"
                + artifactId
                + ":"
                + version;
    }
}