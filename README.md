# crl-monitor

[![Build Status](https://github.com/letsencrypt/crl-monitor/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/letsencrypt/crl-monitor/actions/workflows/test.yml?query=branch%3Amain)

CRL-Monitor monitors CRLs

## Architecture Diagram

```mermaid
sequenceDiagram
  participant churn as Certificate Churner<br />Lambda
  participant ca as Let's Encrypt<br />Certification Authority
  participant ddb as Pending Certificates<br />DynamoDB
  participant s3 as CRL Storage<br />S3 Bucket
  participant ccl as CRL Checker<br />Lambda

  loop timer
    churn->>ca: Issue certificate
    activate churn
    churn->>ca: Revoke certificate
    churn->>ddb: Store certificate metadata
    deactivate churn
  end

  loop New CRL
    ca->>s3: Publish CRL Shard
    s3->>ccl: S3 Event
    activate ccl
    ccl->>s3: Read current CRL
    ccl->>s3: Read previous CRL
    Note over ccl: Alert if CRL fails linting
    loop all removed serials
      ccl->>ca: Get Certificate
    end
    Note over ccl: Alert if CRL had any serials leave early
    ccl->>ddb: Get revoked serials
    ccl->>ddb: Delete seen serials
    Note over ccl: Alert if any expected serials<br/>missed inclusion deadline
    deactivate ccl
  end
```
