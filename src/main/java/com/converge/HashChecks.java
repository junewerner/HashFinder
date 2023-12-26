package com.converge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import java.util.ArrayList;

public class HashChecks implements ScanCheck{
    List<Pattern> patterns = new ArrayList<Pattern>();
    
    private static final Pattern BCRYPT_PATTERN = Pattern.compile("(\\$2[abxy]|\\$2)\\$\\d{2}\\$[a-z0-9\\/.]{53}", Pattern.CASE_INSENSITIVE);
    private static final Pattern MD5_PATTERN = Pattern.compile("(?<=.{0,20}pass.{0,20})[a-f0-9]{32}", Pattern.CASE_INSENSITIVE); // includes lookbehind to limit non-password hash false positives
    private static final Pattern SHA1_PATTERN = Pattern.compile("[a-f0-9]{40}", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHA256_PATTERN = Pattern.compile("[a-f0-9]{64}", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHA512_PATTERN = Pattern.compile("[a-f0-9]{128}", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCRYPT_PATTERN = Pattern.compile("SCRYPT:\\d+:\\d{1}:\\d{1}:[a-z0-9:\\/+=]+", Pattern.CASE_INSENSITIVE);
    

    private final MontoyaApi api;

    HashChecks(MontoyaApi api)
    {
        this.api = api;
        this.patterns.add(BCRYPT_PATTERN);
        this.patterns.add(MD5_PATTERN);
        this.patterns.add(SHA1_PATTERN);
        this.patterns.add(SHA256_PATTERN);
        this.patterns.add(SHA512_PATTERN);
        this.patterns.add(SCRYPT_PATTERN);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
        List<AuditIssue> auditIssueList = emptyList();
        return auditResult(auditIssueList);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        List<Marker> responseHighlights = new ArrayList<Marker>();
        for (Pattern pattern : this.patterns) {
            responseHighlights.addAll(getResponseHighlights(baseRequestResponse, pattern));
        }
        

        List<AuditIssue> auditIssueList = responseHighlights.isEmpty() ? emptyList() : singletonList(
                auditIssue(
                        "Possible Password Hash Detected",
                        "The response contains a string which appears to be a password hash. Manual confirmation is requried to identify if this is a false positive.",
                        null,
                        baseRequestResponse.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.TENTATIVE,
                        null,
                        null,
                        AuditIssueSeverity.HIGH,
                        baseRequestResponse.withResponseMarkers(responseHighlights)
                )
        );

        return auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private static List<Marker> getResponseHighlights(HttpRequestResponse requestResponse, Pattern pattern)
    {
        List<Marker> highlights = new LinkedList<>();
        String response = requestResponse.response().bodyToString();
        Matcher matcher = pattern.matcher(response);
        
        while (matcher.find()) {
            Marker marker = Marker.marker(matcher.start(), matcher.end());
            highlights.add(marker);
        }
        
        return highlights;
    }
}
