(ns strojure.web-security.csp
  "Content Security Policy (CSP).

  See https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP.
  "
  (:require [strojure.web-security.csp-impl :as impl]
            [strojure.web-security.util.random :as random]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; ## CSP Header ##

(defn header-name
  "Returns CSP header name, normal one or report-only if `report-only` is true.
  Without argument returns normal header name."
  ([] (header-name false))
  ([report-only]
   (if report-only "Content-Security-Policy-Report-Only"
                   "Content-Security-Policy")))

(defn header-value-fn
  "The returned function takes a `policy` map and returns a content policy
  header value. If the policy map contains `:nonce` in directive values, the
  returned function is a 1-arity function `(fn [nonce] policy-header)`,
  otherwise it is a 0-arity function.

  The keys in the policy map represent directive names, and can be:

  - string, which is taken as is
  - keyword, which are converted to string using `name`
  - other type which implements `as-directive-name` of [[csp-impl/PolicyRender]]
    protocol

  The values in the policy map represent directive values, and can be:

  - string, which is taken as is
  - keyword
      - the special `:nonce` keyword is a placeholder for the value of nonce
      - other keywords are converted to single quoted string using `name`
  - collection, where elements are rendered as directive values and
    separated with space.
  - other type which implements `write-directive-value` of
    [[csp-impl/PolicyRender]] protocol

  Example:

      (def nonce-policy
        (csp/header-value-fn {\"script-src\" :nonce
                              \"img-src\" \"*\"}))

      (nonce-policy \"MY-NONCE\")
      :=> \"script-src 'nonce-MY-NONCE'; img-src *\"

      (def static-policy
        (csp/header-value-fn {:default-src [\"https:\"
                                            :unsafe-eval
                                            :unsafe-inline]
                              :object-src :none})

      (static-policy)
      :=> \"default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'\"

  CSP header values can be tested online:

  - [CSP Evaluator](https://csp-evaluator.withgoogle.com/).
  - [The Mozilla Observatory](https://observatory.mozilla.org/).
  "
  [policy]
  (let [[s ss & more :as sss] (-> (impl/render-header-value policy)
                                  (impl/split-nonce))]
    (cond more, ^::nonce (fn multiple-nonce
                           [nonce] (transduce (interpose nonce) impl/sb-append sss))
          ss,,, ^::nonce (fn singe-nonce
                           [nonce] (-> ^String s
                                       (.concat nonce)
                                       (.concat ss)))
          :else,,,,,,,,, (fn static-string
                           [] s))))

(defn requires-nonce?
  "True if result of the [[header-value-fn]] requires nonce argument."
  [f]
  (some-> (meta f) ::nonce))

(defn find-directive
  "Returns directive value from the `policy` map for the given `policy-name`."
  [policy-name policy]
  (let [policy-name (impl/as-directive-name policy-name)
        matched-value (fn matched-value [[k v]]
                        (when (= policy-name (impl/as-directive-name k)) v))]
    (some matched-value policy)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; ## CSP Nonce ##

(defn random-nonce-fn
  "Returns unique random 128 bit URL-safe string (22 chars) to be used as CSP
  nonce in HTTP response. Implemented with [[util.random/url-safe-string-fn]].

  Example:

      (def random-nonce (csp/random-nonce-fn))

      (random-nonce) :=> \"AsiTZwAOG_orOX0-4Vw_7g\"
      ;             Execution time mean : 1.074505 µs
      ;    Execution time std-deviation : 63.286135 ns
      ;   Execution time lower quantile : 1.000594 µs ( 2.5%)
      ;   Execution time upper quantile : 1.162035 µs (97.5%)

  See also [Using a nonce with CSP](https://content-security-policy.com/nonce/).
  "
  []
  (random/url-safe-string-fn 16))

(comment
  (def random-nonce (random-nonce-fn))
  (random-nonce) :=> "AsiTZwAOG_orOX0-4Vw_7g"
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
