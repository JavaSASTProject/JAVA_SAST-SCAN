# Java SAST Scanner

Java Static Application Security Testing (SAST) Scanner built using AST-based source code analysis.

## Overview

Java SAST Scanner analyzes Java source code and identifies common security vulnerabilities without executing the application. It performs static code analysis using Abstract Syntax Tree (AST) parsing to detect insecure coding practices.

## Features

- Hardcoded Credential Detection
- SQL Injection Detection
- Cross-Site Scripting (XSS) Detection
- Path Traversal Detection
- Weak Cryptography Detection
- AST-Based Source Code Analysis
- Security Finding Reporting

## Requirements

- Java 17 or later
- Maven 3.8+

## Build

Clone the repository:

```bash
git clone https://github.com/JavaSASTProject/JAVA_SAST-SCAN.git
cd JAVA_SAST-SCAN
```

Build the project:

```bash
mvn clean package
```

## Usage

Run the scanner against a Java project:

```bash
java -jar target/java-sast-scanner.jar <source-directory>
```

Example:

```bash
java -jar target/java-sast-scanner.jar ./sample-project
```

## Vulnerabilities Detected

### Hardcoded Credentials

```java
String password = "admin123";
```

### SQL Injection

```java
String query = "SELECT * FROM users WHERE id=" + userInput;
```

### Cross-Site Scripting (XSS)

```java
response.getWriter().write(request.getParameter("input"));
```

### Path Traversal

```java
new File("/uploads/" + userInput);
```

### Weak Cryptography

```java
MessageDigest.getInstance("MD5");
```

## Sample Output

```text
[HIGH] Hardcoded Credential
File: LoginController.java
Line: 25

[HIGH] SQL Injection
File: UserService.java
Line: 48

[MEDIUM] Weak Cryptography
File: CryptoUtil.java
Line: 14
```

## Future Roadmap

- Support for additional vulnerability rules
- Severity scoring
- CI/CD integration
- Multi-language support

## License

MIT License
