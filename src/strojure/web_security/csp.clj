(ns strojure.web-security.csp
  (:require [clojure.string :as string])
  (:import (clojure.lang IPersistentCollection Keyword)))

(set! *warn-on-reflection* true)

;;
;; ## Implementation protocols ##

(defprotocol PolicyRender
  "A protocol for rendering various types as content policy directives and their
  values."

  (as-directive-name
    [x]
    "Returns string value for directive name.")

  (write-directive-value
    [x rf to]
    "Returns new value of `to` created using reducing function `(fn rf [to string])`.
    The `x` is responsible for the space before it."))

(extend-type String
  PolicyRender
  (as-directive-name [s] s)
  (write-directive-value [s rf to] (-> to (rf " ") (rf s))))

(def ^:private nonce-placeholder "__NONCE__")

(extend-type Keyword
  PolicyRender
  (as-directive-name [k]
    (.getName k))
  (write-directive-value [k rf to]
    (if (.equals :nonce k)
      (-> to (rf " 'nonce-") (rf nonce-placeholder) (rf "'"))
      ;; Wrap keyword with single quotes.
      (-> to (rf " '") (rf (.getName k)) (rf "'")))))

(extend-type IPersistentCollection
  PolicyRender
  (write-directive-value [coll rf to]
    (reduce (fn [to x] (write-directive-value x rf to)) to coll)))

;;
;; ## Policy header ##

(defn- sb-append
  "Reducing function which appends string to `StringBuilder`."
  ([] (StringBuilder.))
  ([sb] (.toString ^StringBuilder sb))
  ([sb s] (.append ^StringBuilder sb ^String s)))

(defn- render-policy
  "Returns content policy header string for the `policy` map.
  See [[policy-header-fn]] for the description of policy map."
  [policy]
  (-> (let [empty?! (volatile! true)]
        (fn [sb k v]
          (as-> sb to
            (if (.deref empty?!)
              (do (vreset! empty?! false)
                  to)
              (sb-append to "; "))
            (sb-append to (as-directive-name k))
            (write-directive-value v sb-append to))))
      (reduce-kv (sb-append) policy)
      (sb-append)))

(let [nonce-pattern (re-pattern nonce-placeholder)]

  (defn policy-header-fn
    "The returned function takes a `policy` map and returns a content policy
    header string. If the policy map contains `:nonce` in directive values, the
    returned function is a 1-arity function `(fn [nonce] policy-header)`,
    otherwise it is a 0-arity function.

    The keys in the policy map represent directive names, and can be strings,
    keywords (which are converted to strings using `name`), or other types which
    provide an implementation of [[as-directive-name]].

    The keys in the policy map represent directive names, and can be:

    - string, which is taken as is
    - keyword, which are converted to string using `name`
    - other type which provides implementation of [[as-directive-name]]

    The values in the policy map represent directive values, and can be:

    - string, which is taken as is
    - keyword
        - the special `:nonce` keyword is a placeholder for the value of nonce
        - other keywords are converted to single quoted string using `name`
    - collection, where elements are rendered as directive values and
      separated with space.
    - other type which provides implementation of [[write-directive-value]]

        (def nonce-policy
          (csp/policy-header-fn {\"script-src\" :nonce
                                 \"img-src\" \"*\"}))

        (nonce-policy \"MY-NONCE\")
        :=> \"script-src 'nonce-MY-NONCE'; img-src *\"

        (def static-policy
          (csp/policy-header-fn {:default-src [\"https:\"
                                               :unsafe-eval
                                               :unsafe-inline]
                                 :object-src :none})

        (static-policy)
        :=> \"default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'\"
    "
    [policy]
    (let [[s ss & more :as sss] (-> (render-policy policy)
                                    (string/split nonce-pattern -1))]
      (cond more, (fn multiple-nonce
                    [nonce] (transduce (interpose nonce) sb-append sss))
            ss,,, (fn singe-nonce
                    [nonce] (-> ^String s
                                (.concat nonce)
                                (.concat ss)))
            :else (fn static-string
                    [] s)))))

;;
;; ## Nonce generation ##


