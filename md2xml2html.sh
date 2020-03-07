#!/bin/bash

kramdown-rfc2629 draft-parecki-oauth-v2-1.md | xml2rfc -q --v2v3 /dev/stdin -o build/draft-parecki-oauth-v2-1.xml

xml2rfc --html --css=build/v3.css build/draft-parecki-oauth-v2-1.xml
xml2rfc build/draft-parecki-oauth-v2-1.xml
