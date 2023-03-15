# web-security

Decoupled web security implementations for Clojure.

[![Clojars Project](https://img.shields.io/clojars/v/com.github.strojure/web-security.svg)](https://clojars.org/com.github.strojure/web-security)

[![cljdoc badge](https://cljdoc.org/badge/com.github.strojure/web-security)](https://cljdoc.org/d/com.github.strojure/web-security)
[![tests](https://github.com/strojure/web-security/actions/workflows/tests.yml/badge.svg)](https://github.com/strojure/web-security/actions/workflows/tests.yml)

## Motivation

Provide [web security] implementations decoupled from any of http abstractions
like ring, pedestal etc.

[web security]: https://developer.mozilla.org/en-US/docs/Web/Security

## API

### Content Security Policy (CSP)

Functions implementing CSP:

- [csp/header-name] returns normal or report-only name of the CSP header.
- [csp/header-value-fn] builds function for CSP header value from policy map,
  supports dynamic nonce substitution.
- [csp/requires-nonce?] tests if result of the `header-value-fn` requires nonce
  argument
- [csp/find-directive] return policy directive value from the policy map
- [csp/random-nonce-fn] returns function to generate nonce values to be used in
  HTTP response.

[csp/header-name]:
https://cljdoc.org/d/com.github.strojure/web-security/CURRENT/api/strojure.web-security.csp#header-name

[csp/header-value-fn]:
https://cljdoc.org/d/com.github.strojure/web-security/CURRENT/api/strojure.web-security.csp#header-value-fn

[csp/requires-nonce?]:
https://cljdoc.org/d/com.github.strojure/web-security/CURRENT/api/strojure.web-security.csp#requires-nonce?

[csp/find-directive]:
https://cljdoc.org/d/com.github.strojure/web-security/CURRENT/api/strojure.web-security.csp#find-directive

[csp/random-nonce-fn]:
https://cljdoc.org/d/com.github.strojure/web-security/CURRENT/api/strojure.web-security.csp#random-nonce-fn

---

Authored by [Sergey Trofimov](https://github.com/serioga).

[![license](https://img.shields.io/badge/license-The%20Unlicense-informational)](UNLICENSE)
