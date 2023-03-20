(ns strojure.web-security.referrer-policy-test
  (:require [clojure.test :as test :refer [deftest]]
            [strojure.web-security.referrer-policy :as referrer-policy]))

(set! *warn-on-reflection* true)

(declare thrown?)

;;--------------------------------------------------------------------------------------------------

(deftest header-name-t

  (test/is (= "Referrer-Policy"
              referrer-policy/header-name))

  )

(deftest header-value-t

  (test/is (= nil
              (referrer-policy/header-value nil)))

  (test/is (= nil
              (referrer-policy/header-value false)))

  (test/is (= "strict-origin-when-cross-origin"
              (referrer-policy/header-value true)))

  (test/is (= "strict-origin"
              (referrer-policy/header-value :strict-origin)))

  (test/is (= "no-referrer"
              (referrer-policy/header-value :referrer-policy/no-referrer)))

  (test/is (= "no-referrer-when-downgrade"
              (referrer-policy/header-value "no-referrer-when-downgrade")))

  )

;;--------------------------------------------------------------------------------------------------
