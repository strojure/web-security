(ns strojure.web-security.util.base64
  (:import (java.util Base64)))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(let [encoder (-> (Base64/getUrlEncoder) .withoutPadding)]

  (defn url-encode-no-padding
    "Returns string of byte array `data` URL encoded without padding."
    {:added "1.2"}
    [^bytes data]
    (.encodeToString encoder data)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
