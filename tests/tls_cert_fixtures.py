# SPDX-License-Identifier: GPL-3.0-or-later
"""
Certificats X.509 auto-signes a algorithme FAIBLE, generes avec openssl 3.0
(issue #153) : `cryptography` refuse de SIGNER en SHA-1/MD5, ces deux cas ne
peuvent donc pas etre fabriques a la volee par les tests. DER en base64 ;
valeurs de test uniquement, cles privees jetees.

    openssl req -x509 -newkey rsa:1024 -nodes -keyout /dev/null -days 300 -sha1 \\
        -subj "/CN=weak.lab.test/O=Lab" -addext "subjectAltName=DNS:weak.lab.test"
    openssl req -x509 -newkey rsa:1024 -nodes -keyout /dev/null -days 3650 -md5 \\
        -subj "/CN=md5.lab.test"
"""

# sha1WithRSAEncryption, RSA 1024 bits, CN=weak.lab.test,O=Lab, SAN DNS weak.lab.test
SHA1_RSA1024_DER_B64 = (
    "MIICQjCCAaugAwIBAgIUUF2RP+mBsYEcE9fBqoPIAJl6SgwwDQYJKoZIhvcNAQEFBQAwJjEWMBQGA1UEAwwNd2Vhay5sYWIudGVz"
    "dDEMMAoGA1UECgwDTGFiMB4XDTI2MDkyMTE4NDAwMFoXDTI3MDcxODE4NDAwMFowJjEWMBQGA1UEAwwNd2Vhay5sYWIudGVzdDEM"
    "MAoGA1UECgwDTGFiMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHLaatuGufx0w5+K8tWpvfzkdIWSY2xKnnSbVC+s9bcap0"
    "xWDhMtwIpsFSjVV7D5HdxfbeD9Pxq+xNtmCeGnh0hBUGBislN26DJB4aj7NlecMsMdDf7Aq5HYR1qt5YtIK6AVmGWxNW/hLmWclx"
    "69Q3yO0Dt3P7Pry2QWeXXfuxkQIDAQABo20wazAdBgNVHQ4EFgQUX0ZWWa1v8TtY0aAnlIZJ3TwwS/kwHwYDVR0jBBgwFoAUX0ZW"
    "Wa1v8TtY0aAnlIZJ3TwwS/kwDwYDVR0TAQH/BAUwAwEB/zAYBgNVHREEETAPgg13ZWFrLmxhYi50ZXN0MA0GCSqGSIb3DQEBBQUA"
    "A4GBAKux/jwP49GtZl8/CWmwhI6TeVaYHH+ZNrQ2FP/J2lJwmxb7ZqLDyca6Vi4pNP94zcbnhgr7mLIBbM74qIbeNBmHvhRl336o"
    "nh6YfGHt5/nq4xTDGueIEADLNvc1h/yxDApn0gA5cpZ3UjZOubmyWu59SeaQiDRBrxyZ+dEmG1Qb"
)

# md5WithRSAEncryption, RSA 1024 bits, CN=md5.lab.test
MD5_RSA1024_DER_B64 = (
    "MIICCjCCAXOgAwIBAgIUN5v0Ad0IFg81WQpVmPJAw5HPYikwDQYJKoZIhvcNAQEEBQAwFzEVMBMGA1UEAwwMbWQ1LmxhYi50ZXN0"
    "MB4XDTI2MDkyMTE4NDk1N1oXDTM2MDkxODE4NDk1N1owFzEVMBMGA1UEAwwMbWQ1LmxhYi50ZXN0MIGfMA0GCSqGSIb3DQEBAQUA"
    "A4GNADCBiQKBgQC4j6H1cPO/YV2kW0gYUrWpDBb4dKke5MBBJqSw4Y6LAB8NWIhyvlppRBUXt9f4upUfcJqh7mHeIR7+yOb24XVe"
    "913EXIqfbrUYr4UlKvC2Wje1kaJiY54/wqV3r+RhdZwAuQre0U0sNIaVoCyapG8i01wSTEnR268H/o8O6Gw66QIDAQABo1MwUTAd"
    "BgNVHQ4EFgQUNsocWppctXh69+U14RjsU7Be7bIwHwYDVR0jBBgwFoAUNsocWppctXh69+U14RjsU7Be7bIwDwYDVR0TAQH/BAUw"
    "AwEB/zANBgkqhkiG9w0BAQQFAAOBgQC15QnBri/Hhb+VZaX/IbrpsF9JW5l85ycVKXqJEY34EsHEXyiRkzs7s0wZrLPTIg2UnAx1"
    "e7Ep22+MRBfNhxULJ7jpmCac+x98ves+ygetrtrQsUilD2Bc8KSkMCUV787WhYU4I0Mx0DaBrfztOUnOZxNr5vjdZc4T8dp+VZB/"
    "cg=="
)
