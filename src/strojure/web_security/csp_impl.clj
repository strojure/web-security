(ns strojure.web-security.csp-impl
  (:import (clojure.lang IPersistentCollection Keyword)))

(set! *warn-on-reflection* true)

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

(def ^:const nonce-placeholder
  "The replacement for the `:nonce` to be substituted with CSP nonce value."
  "__NONCE__")

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

(defn sb-append
  "Reducing function which appends string to `StringBuilder`."
  ([] (StringBuilder.))
  ([sb] (.toString ^StringBuilder sb))
  ([sb s] (.append ^StringBuilder sb ^String s)))

(defn render-header-value
  "Returns content policy header value for the `policy` map.
  See [[csp/header-value-fn]] for the description of policy map."
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
