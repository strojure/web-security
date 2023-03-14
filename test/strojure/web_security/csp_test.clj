(ns strojure.web-security.csp-test
  (:require [clojure.test :as test :refer [deftest testing]]
            [strojure.web-security.csp :as csp])
  (:import (java.security SecureRandom)))

(set! *warn-on-reflection* true)

;;--------------------------------------------------------------------------------------------------

(deftest header-name-t

  (test/is (= "Content-Security-Policy"
              (csp/header-name)))

  (test/is (= "Content-Security-Policy"
              (csp/header-name false)))

  (test/is (= "Content-Security-Policy-Report-Only"
              (csp/header-name true)))

  )

(deftest header-value-fn-t

  (testing "String keys"

    (test/is "default-src *"
             ((csp/header-value-fn (sorted-map "default-src" "*"))))

    (test/is "default-src *; image-src *"
             ((csp/header-value-fn (sorted-map "default-src" "*"
                                               "image-src" "*"))))

    (test/is "default-src *; image-src *"
             ((csp/header-value-fn (sorted-map "image-src" "*"
                                               "default-src" "*"))))

    )

  (testing "Keyword keys"

    (test/is "default-src *"
             ((csp/header-value-fn (sorted-map :default-src "*"))))

    (test/is "default-src *; image-src *"
             ((csp/header-value-fn (sorted-map :default-src "*"
                                               :image-src "*"))))

    (test/is "default-src *"
             ((csp/header-value-fn (sorted-map :csp/default-src "*"))))

    (test/is "default-src *; image-src *"
             ((csp/header-value-fn (sorted-map :csp/default-src "*"
                                               :csp/image-src "*"))))

    )

  (testing "String values"

    (test/is "default-src https:; image-src 'self'"
             ((csp/header-value-fn (sorted-map "default-src" "https:"
                                               "image-src" "'self'"))))

    )

  (testing "Keyword values"

    (test/is "default-src 'none'; image-src 'self'"
             ((csp/header-value-fn (sorted-map "default-src" :none
                                               "image-src" :self))))

    )

  (testing "Collection values"

    (test/is "default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'"
             ((csp/header-value-fn (sorted-map "default-src" ["https:" :unsafe-eval :unsafe-inline]
                                               "object-src" [:none]))))

    )

  (testing "Policy with nonce"

    (test/is "default-src 'none'; script-src 'nonce-TEST-NONCE'"
             ((csp/header-value-fn (sorted-map "default-src" :none
                                               "script-src" :nonce))
              "TEST-NONCE"))

    (test/is "script-src 'nonce-TEST-NONCE'; style-src 'self' 'nonce-TEST-NONCE'"
             ((csp/header-value-fn (sorted-map "script-src" :nonce
                                               "style-src" [:self :nonce]))
              "TEST-NONCE"))

    )

  )

(deftest random-nonce-fn-t

  (test/is (string? ((csp/random-nonce-fn))))

  (test/is (<= 24 (count ((csp/random-nonce-fn)))))

  (test/is (string? ((csp/random-nonce-fn (SecureRandom.)))))

  )

;;--------------------------------------------------------------------------------------------------
