FROM occlum/occlum:latest-ubuntu22.04
LABEL authors="Vencel Bajnok"
LABEL maintainer="bajnokvencel@edu.bme.hu"
LABEL description="Docker image for running the CMCaaS server on an Intel SGX enabled hardware using Occlum."
LABEL version="1.0.0"

# Install necessary packages
RUN apt-get update && apt-get install -y openjdk-21-jdk maven jq supervisor sqlite3 python3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu

WORKDIR /app

COPY src/server /app/src/server/
COPY scripts/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN cd src/server && mvn clean package

COPY src/enclave /app/src/enclave/
COPY src/client /app/src/client/
COPY scripts /app/scripts/

RUN chmod +x /app/scripts/*
RUN chmod +x /app/src/enclave/theta/*.sh
RUN chmod +x /app/src/enclave/theta/*.jar

RUN javac src/enclave/VerifierRunner.java -d /app/src/enclave/
RUN javac src/client/RemoteClient.java -d /app/src/client/

WORKDIR /app

EXPOSE 8080
ENTRYPOINT ["/usr/bin/supervisord"]
