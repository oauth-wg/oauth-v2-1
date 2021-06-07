FROM python:3-slim-buster

RUN apt-get update
RUN pip install xml2rfc

RUN apt-get install -y ruby-full

RUN gem install kramdown
RUN gem install kramdown-rfc2629

WORKDIR /usr/local/bin

COPY convert-v2-1.sh /usr/local/bin/convert-v2-1.sh

WORKDIR /data

ENTRYPOINT [ "/bin/bash","/usr/local/bin/convert-v2-1.sh"]