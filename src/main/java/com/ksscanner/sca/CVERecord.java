package com.ksscanner.sca;

public class CVERecord {

    private final String packageName;
    private final String version;
    private final String cve;
    private final String severity;
    private final String cvss;
    private final String description;
    private final String recommendation;
    private final String reference;

    public CVERecord(
            String packageName,
            String version,
            String cve,
            String severity,
            String cvss,
            String description,
            String recommendation,
            String reference) {

        this.packageName = packageName;
        this.version = version;
        this.cve = cve;
        this.severity = severity;
        this.cvss = cvss;
        this.description = description;
        this.recommendation = recommendation;
        this.reference = reference;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getVersion() {
        return version;
    }

    public String getCve() {
        return cve;
    }

    public String getSeverity() {
        return severity;
    }

    public String getCvss() {
        return cvss;
    }

    public String getDescription() {
        return description;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public String getReference() {
        return reference;
    }
}