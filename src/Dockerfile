FROM python:3.10-slim
LABEL authors="pixel"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    can-utils \
    socat  && \
    rm -rf /var/lib/apt/lists/*

RUN pip install scapy
# RUN modprobe vcan # && \
#    ip link add dev vcan0 type vcan && \
#    ip link set up vcan0
COPY chall /chall
WORKDIR /chall
RUN chmod +x run.sh

ENTRYPOINT ["./run.sh"]