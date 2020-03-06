#!/bin/bash

cat draft-parecki-oauth-v2_1.md | kramdown-rfc2629 | xml2rfc -q --v2v3 /dev/stdin -o build/draft-parecki-oauth-v2_1.xml

xml2rfc --html --css=build/v3.css build/draft-parecki-oauth-v2_1.xml