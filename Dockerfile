FROM python:3.7.4-alpine3.9

WORKDIR /usr/src/xmlchecker
COPY . /usr/src/xmlchecker

ENTRYPOINT ["./XMLCheck.py"]
