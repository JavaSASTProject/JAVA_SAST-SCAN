# Java SAST Scanner

Java Static Application Security Testing (SAST) Scanner built using AST-based source code analysis.

## Features

- SQL Injection Detection
- Command Injection Detection
- LDAP Injection Detection
- XPath Injection Detection
- NoSQL Injection Detection
- Authentication Security Checks
- Cryptography Security Checks
- Input Validation Checks
- File Handling Security Checks
- OWASP Top 10 Mapping
- CWE Mapping
- HTML Report Generation
- CSV Report Generation

## Build

```bash
mvn clean package
```

## Run

```bash
java -jar target/SCAScanner-v1.0.jar <source-code-directory>
```

## Requirements

- Java 17+
- Maven 3.8+
