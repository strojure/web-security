(ns strojure.web-security.csp
  "Content Security Policy (CSP).

  See https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP.
  "
  (:require [clojure.string :as string]
            [strojure.web-security.csp-impl :as impl])
  (:import (java.security SecureRandom)
           (java.util Base64 Random)))

(set! *warn-on-reflection* true)

;;--------------------------------------------------------------------------------------------------
;; ## CSP Header ##

(defn header-name
  "Returns CSP header name, normal one or report-only if `report-only` is true.
  Without argument returns normal header name."
  ([] (header-name false))
  ([report-only]
   (if report-only "Content-Security-Policy-Report-Only"
                   "Content-Security-Policy")))

(let [nonce-pattern (re-pattern impl/nonce-placeholder)]

  (defn header-value-fn
    "The returned function takes a `policy` map and returns a content policy
    header value. If the policy map contains `:nonce` in directive values, the
    returned function is a 1-arity function `(fn [nonce] policy-header)`,
    otherwise it is a 0-arity function.

    The keys in the policy map represent directive names, and can be strings,
    keywords (which are converted to strings using `name`), or other types which
    provide an implementation of [[csp_impl/as-directive-name]].

    The keys in the policy map represent directive names, and can be:

    - string, which is taken as is
    - keyword, which are converted to string using `name`
    - other type which provides implementation of [[csp_impl/as-directive-name]]

    The values in the policy map represent directive values, and can be:

    - string, which is taken as is
    - keyword
        - the special `:nonce` keyword is a placeholder for the value of nonce
        - other keywords are converted to single quoted string using `name`
    - collection, where elements are rendered as directive values and
      separated with space.
    - other type which provides implementation of
      [[csp_impl/write-directive-value]]


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
                                    (string/split nonce-pattern -1))]
      (cond more, (fn multiple-nonce
                    [nonce] (transduce (interpose nonce) impl/sb-append sss))
            ss,,, (fn singe-nonce
                    [nonce] (-> ^String s
                                (.concat nonce)
                                (.concat ss)))
            :else (fn static-string
                    [] s)))))

;;--------------------------------------------------------------------------------------------------
;; ## CSP Nonce ##

(defn random-nonce-fn
  "Returns unique random 144 bit string (24 chars) to be used as CSP nonce in
  HTTP response. Uses `java.security SecureRandom` or provided optional instance
  of `java.util.Random` to generate random bytes.


      (def random-nonce (csp/random-nonce-fn))

      (random-nonce) :=> \"iqkOHbaBPnGT6vC73ph89/G3\"
      ;             Execution time mean : 1.042166 µs
      ;    Execution time std-deviation : 30.633099 ns
      ;   Execution time lower quantile : 1.009274 µs ( 2.5%)
      ;   Execution time upper quantile : 1.087203 µs (97.5%)


  See also [Using a nonce with CSP](https://content-security-policy.com/nonce/).
  "
  ([] (random-nonce-fn (as-> (SecureRandom.) random
                         (doto random (.setSeed (.generateSeed random 18))))))
  ([^Random random]
   (fn []
     (let [b (byte-array 18)]
       (.nextBytes random b)
       (.encodeToString (Base64/getEncoder) b)))))

(comment
  (def random-nonce (random-nonce-fn))
  (random-nonce) :=> "iqkOHbaBPnGT6vC73ph89/G3"
  )

;;--------------------------------------------------------------------------------------------------
