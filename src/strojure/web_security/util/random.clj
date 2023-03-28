(ns strojure.web-security.util.random
  (:require [strojure.web-security.util.base64 :as base64])
  (:import (java.security SecureRandom)))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn random-string-fn
  "Returns 0-arity function to generate random byte array of `size` bytes
  encoded with function `encode`. Uses instance of `SecureRandom` to generate
  random data."
  {:added "1.2"}
  [encode, size]
  (let [random (SecureRandom.)]
    (fn []
      (let [data (byte-array size)]
        (.nextBytes random data)
        (encode data)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn url-safe-string-fn
  "Returns 0-arity function to generate random byte array of `size` bytes which
  is URL encoded without padding (16 bytes produce 22-char string). Uses
  [[random-string-fn]] with [[base64/url-encode-no-padding]] as `encode-fn`.

  Example:

      (def url-safe-string (url-safe-string-fn 16))

      (url-safe-string)
      :=> \"CAAuS3CWaMZqh490vfoFWA\"
      ;             Execution time mean : 1.134222 µs
      ;    Execution time std-deviation : 141.224567 ns
      ;   Execution time lower quantile : 1.060196 µs ( 2.5%)
      ;   Execution time upper quantile : 1.378707 µs (97.5%)
  "
  {:added "1.2"}
  [size]
  (random-string-fn base64/url-encode-no-padding size))

(comment
  (def url-safe-string (url-safe-string-fn 16))
  (url-safe-string) :=> "CAAuS3CWaMZqh490vfoFWA"
  (count (url-safe-string)) :=> 22
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
