(ns strojure.web-security.referrer-policy
  "The [Referrer-Policy] HTTP header controls how much referrer information
  (sent with the Referer header) should be included with requests.

  [Referrer-Policy]:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
  "
  (:import (clojure.lang Keyword)))

(set! *warn-on-reflection* true)

;;--------------------------------------------------------------------------------------------------

(def ^:const ^String header-name
  "Returns \"Referrer-Policy\" string."
  "Referrer-Policy")

(defprotocol ReferrerPolicyHeader
  (header-value
    ^java.lang.String [obj]
    "Returns string value for the [Referrer-Policy] response header.

    - \"strict-origin-when-cross-origin\" for boolean `true`
    - string as is for strings
    - keyword name for keywords

    [Referrer-Policy]:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
    "))

(extend-protocol ReferrerPolicyHeader
  nil (header-value [_] nil)
  String (header-value [s] s)
  Boolean (header-value [b] (when b "strict-origin-when-cross-origin"))
  Keyword (header-value [k] (name k)))

;;--------------------------------------------------------------------------------------------------
