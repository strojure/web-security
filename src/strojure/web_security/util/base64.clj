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

(defn estimated-strlen
  "Returns min length of base64 encoded string for byte array of `size` bytes,
  without padding."
  {:added "1.3"}
  [size]
  (int (-> size (/ 3) (* 4))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
