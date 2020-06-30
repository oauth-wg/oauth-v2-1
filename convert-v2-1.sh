#!/bin/bash

# Compile the markdown to v2 XML, then use xml2rfc to convert to v3 XML
kramdown-rfc2629 draft-parecki-oauth-v2-1.md | xml2rfc -q --v2v3 /dev/stdin -o build/draft-parecki-oauth-v2-1.xml

# Build the text version
xml2rfc build/draft-parecki-oauth-v2-1.xml

# Build the HTML version
xml2rfc --html --v3 build/draft-parecki-oauth-v2-1.xml
