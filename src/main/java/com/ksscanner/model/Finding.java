package com.ksscanner.model;

public class Finding {

    private String rule;
    private String category;
    private String severity;
    private String confidence;

    private String cwe;
    private String owasp;

    private String message;
    private String recommendation;

    private String file;
    private int line;
    private int column;

    private String snippet;

    // Optional data-flow information
    private String source;
    private String sink;


    /*
     * =========================================================
     * BACKWARD COMPATIBLE CONSTRUCTOR
     * =========================================================
     *
     * Keeps your existing rules working.
     */
    public Finding(
            String rule,
            String severity,
            String cwe,
            String owasp,
            String message,
            String file,
            int line,
            String snippet) {

        this(
                rule,
                "Security",
                severity,
                "Medium",
                cwe,
                owasp,
                message,
                "Review the identified code and apply secure coding practices.",
                file,
                line,
                0,
                snippet,
                "",
                ""
        );
    }


    /*
     * =========================================================
     * FULL CONSTRUCTOR
     * =========================================================
     */
    public Finding(
            String rule,
            String category,
            String severity,
            String confidence,
            String cwe,
            String owasp,
            String message,
            String recommendation,
            String file,
            int line,
            int column,
            String snippet,
            String source,
            String sink) {

        this.rule = rule;
        this.category = category;
        this.severity = severity;
        this.confidence = confidence;

        this.cwe = cwe;
        this.owasp = owasp;

        this.message = message;
        this.recommendation = recommendation;

        this.file = file;
        this.line = line;
        this.column = column;

        this.snippet = snippet;

        this.source = source;
        this.sink = sink;
    }


    public String getRule() {
        return rule;
    }

    public String getCategory() {
        return category;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getCwe() {
        return cwe;
    }

    public String getOwasp() {
        return owasp;
    }

    public String getMessage() {
        return message;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public String getFile() {
        return file;
    }

    public int getLine() {
        return line;
    }

    public int getColumn() {
        return column;
    }

    public String getSnippet() {
        return snippet;
    }

    public String getSource() {
        return source;
    }

    public String getSink() {
        return sink;
    }


    /*
     * =========================================================
     * toString()
     * =========================================================
     */
    @Override
    public String toString() {

        return "\n[" + severity + "] "
                + rule

                + "\nCategory   : "
                + category

                + "\nConfidence : "
                + confidence

                + "\nCWE        : "
                + cwe

                + "\nOWASP      : "
                + owasp

                + "\nFile       : "
                + file

                + "\nLine       : "
                + line

                + "\nColumn     : "
                + column

                + "\nMessage    : "
                + message

                + "\nRecommendation: "
                + recommendation

                + "\nSource     : "
                + source

                + "\nSink       : "
                + sink

                + "\nSnippet:\n"
                + snippet;
    }
}