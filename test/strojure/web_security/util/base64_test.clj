(ns strojure.web-security.util.base64-test
  (:require [clojure.test :as test :refer [deftest]]
            [strojure.web-security.util.base64 :as base64]))

(set! *warn-on-reflection* true)

(declare thrown?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest estimated-strlen-t

  (test/is (= 22 (base64/estimated-strlen 16)))

  (test/is (= 42 (base64/estimated-strlen 32)))

  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
