(ns strojure.web-security.hsts-test
  (:require [clojure.test :as test :refer [deftest]]
            [strojure.web-security.hsts :as hsts]))

(set! *warn-on-reflection* true)

(declare thrown?)

;;--------------------------------------------------------------------------------------------------

(deftest header-name-t

  (test/is (= "Strict-Transport-Security"
              hsts/header-name))

  )

(deftest header-value-t

  (test/is (= nil
              (hsts/header-value nil)))

  (test/is (= nil
              (hsts/header-value false)))

  (test/is (= "max-age=31536000"
              (hsts/header-value true)))

  (test/is (= "max-age=31536000; includeSubDomains; preload"
              (hsts/header-value "max-age=31536000; includeSubDomains; preload")))

  )

;;--------------------------------------------------------------------------------------------------
