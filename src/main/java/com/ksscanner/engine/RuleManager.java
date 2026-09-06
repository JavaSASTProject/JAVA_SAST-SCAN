package com.ksscanner.engine;

import com.github.javaparser.ast.CompilationUnit;
import com.ksscanner.model.Finding;
import com.ksscanner.rules.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class RuleManager {

    private final List<Rule> rules = new ArrayList<>();

public RuleManager() {

    rules.add(new AccessControlRules());
    rules.add(new InjectionRules());
    rules.add(new CryptoRules());
    rules.add(new CredentialRules());
    rules.add(new WebSecurityRules());
    rules.add(new LoggingRules());
    rules.add(new ErrorHandlingRules());
    rules.add(new ResourceRules());
    rules.add(new FileHandlingRules());
    rules.add(new CodeQualityRules());
    rules.add(new PerformanceRules());
    rules.add(new ConcurrencyRules());
    rules.add(new InformationDisclosureRules());
    rules.add(new AuthenticationRules());
    rules.add(new PortabilityRules());

    rules.add(new DeserializationRules());
    rules.add(new XXERules());
    rules.add(new SSRFRules());
    rules.add(new SessionManagementRules());
    rules.add(new SecretsRules());
    rules.add(new APISecurityRules());
}


    public List<Finding> analyze(
            CompilationUnit cu,
            String fileName,
            Path filePath) {

        List<Finding> findings =
                new ArrayList<>();

        for (Rule rule : rules) {

            try {

                List<Finding> ruleFindings =
                        rule.analyze(
                                cu,
                                fileName,
                                filePath);

                if (ruleFindings != null) {
                    findings.addAll(ruleFindings);
                }

            } catch (Exception e) {

                System.err.println(
                        "[WARNING] Rule group failed: "
                                + rule.getClass()
                                .getSimpleName());

                System.err.println(
                        "Reason: "
                                + e.getMessage());
            }
        }

        return findings;
    }


    public int getRuleGroupCount() {
        return rules.size();
    }


    public List<Rule> getRules() {
        return rules;
    }
}