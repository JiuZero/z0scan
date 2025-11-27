FROM python:3.10.5-alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update
RUN apk --no-cache add git build-base libffi-dev libxml2-dev libxslt-dev libressl-dev gcc python3 py3-pip py3-lxml py3-cryptography curl wget ca-certificates

RUN wget -O /tmp/observerward.tar.gz https://github.com/0x727/ObserverWard/releases/latest/download/observerward_linux_amd64.tar.gz && \
    tar -xzf /tmp/observerward.tar.gz -C /tmp/ && \
    mv /tmp/observerward_linux_amd64/observerward /usr/local/bin/ && \
    chmod +x /usr/local/bin/observerward && \
    rm -rf /tmp/observerward*

RUN wget -O /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.15_linux_amd64.zip && \
    unzip /tmp/nuclei.zip -d /tmp/ && \
    mv /tmp/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \

ENV PATH="/usr/local/bin:${PATH}"

ADD . /z0scan/
RUN pip install -r /z0scan/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
WORKDIR /z0scan

ENTRYPOINT ["/bin/ash"]