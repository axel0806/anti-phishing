# Security policy

This project handles access to people's mailboxes, so security reports are taken seriously and wanted privately first.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting: open the repository's **Security** tab, choose **Report a vulnerability**, and describe what you found, how to reproduce it, and the impact. If that is not available to you, contact the maintainer privately through the email on their GitHub profile.

You will get an acknowledgement within a few days. This is a small volunteer project, so there is no bounty and no guaranteed fix time, but real vulnerabilities are prioritised over everything else, and you will be credited if you want.

## In scope

The server (`apps/api`), the dashboard, the browser extension, the Outlook add-in, and the detection pipeline. Of particular interest: authentication and authorisation bypasses, account or invite takeover, token leakage, injection (HTML, SQL, prompt), denial of service from crafted emails or attachments (for example regular-expression blow-ups), and anything that could expose message content or mailbox tokens.

## Not in scope

Findings that need an already compromised server or database, missing hardening on a deployment you configured without TLS, and phishing emails that simply score low (those are detection gaps: report them with the *Detection feedback* issue template, with personal details removed).

## Supported versions

Only the latest `main` is supported. The project is alpha software; see "Project status" in the README.
