#!/bin/bash

kramdown-rfc2629 oauth-v2-0.md > build/oauth-v2-0.xml

# curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-v2-0.xml -F 'modeAsFormat=txt/ascii' -F type=ascii > build/oauth-2.0.txt
# curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-v2-0.xml -F 'modeAsFormat=html/ascii' -F type=ascii > build/oauth-2.0.html

xml2rfc build/oauth-v2-0.xml
xml2rfc --html build/oauth-v2-0.xml
