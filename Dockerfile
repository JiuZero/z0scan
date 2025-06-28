FROM python:3.10.5-alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update
RUN apk --no-cache add git build-base libffi-dev libxml2-dev libxslt-dev libressl-dev gcc python3 py3-pip py3-lxml py3-cryptography
ADD . /z0scan/
RUN pip install -r /z0scan/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
WORKDIR /z0scan

ENTRYPOINT ["/bin/ash"]