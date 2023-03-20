(ns strojure.web-security.hsts
  "The HTTP [Strict-Transport-Security] response header (often abbreviated as
  HSTS) informs browsers that the site should only be accessed using HTTPS, and
  that any future attempts to access it using HTTP should automatically be
  converted to HTTPS.

  [Strict-Transport-Security]:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
  ")

(set! *warn-on-reflection* true)

;;--------------------------------------------------------------------------------------------------

(def ^:const ^String header-name
  "Returns \"Strict-Transport-Security\" string."
  "Strict-Transport-Security")

(defprotocol HstsHeader
  (header-value
    ^java.lang.String [obj]
    "Returns string value for the [Strict-Transport-Security] response header.

    - \"max-age=31536000\" for boolean `true`
    - string as is for strings

    [Strict-Transport-Security]:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
    "))

(extend-protocol HstsHeader
  nil (header-value [_] nil)
  String (header-value [s] s)
  Boolean (header-value [b] (when b "max-age=31536000")))

;;--------------------------------------------------------------------------------------------------
