#!/bin/bash

kramdown-rfc2629 oauth-2.1.md > build/oauth-2.1.xml

#curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-2.1.xml -F 'modeAsFormat=txt/ascii' -F type=ascii > build/oauth-2.1.txt
#curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-2.1.xml -F 'modeAsFormat=html/ascii' -F type=ascii > build/oauth-2.1.html

xml2rfc build/oauth-2.1.xml
xml2rfc --html build/oauth-2.1.xml
