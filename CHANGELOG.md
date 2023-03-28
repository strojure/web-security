# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## `1.3.0-41-SNAPSHOT`

Release date `UNRELEASED`

- (feat api): add `util.base64/estimated-strlen` function

## `1.2.0-38`

Release date `2023-03-28`

- (feat api): add `util.base64/url-encode-no-padding` function
- (feat api): add `util.random/url-safe-string-fn` function
- (refactor): impl `csp/random-nonce-fn` using `url-safe-string-fn`
    + BREAKING: remove 1-arity as considered useless
    + Generated nonce is shorter (22 chars) due to changed data size from 18 to
      16 bytes.

## `1.1.0-32`

Release date `2023-03-20`

- (feat): implement `hsts` response header
- (feat): implement `referrer-policy` response header

## `1.0.0-28`

Release date `2023-03-15`

- (feat api): add `csp/header-name` function
- (feat api): add `csp/header-value-fn` function
- (feat api): add `csp/requires-nonce?` function
- (feat api): add `csp/find-directive` function
- (feat api): add `csp/random-nonce-fn` function
