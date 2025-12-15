FROM occlum/occlum:latest-ubuntu22.04
LABEL authors="Vencel Bajnok"
LABEL maintainer="bajnokvencel@edu.bme.hu"
LABEL description="Docker image for running the CMCaaS server on an Intel SGX enabled hardware using Occlum."
LABEL version="1.0.0"

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
COPY data /app/data/
COPY scripts /app/scripts/

RUN chmod +x /app/scripts/*
RUN chmod +x /app/src/enclave/theta/*.sh
RUN chmod +x /app/src/enclave/theta/*.jar

RUN javac src/enclave/VerifierRunner.java -d /app/src/enclave/
RUN javac src/enclave/BareRunner.java -d /app/src/enclave/

RUN javac src/client/RemoteClient.java -d /app/src/client/
RUN javac src/client/BareClient.java -d /app/src/client/

WORKDIR /app/src/enclave/

RUN rm -rf  dcap_attestation
RUN LD=ld gcc dcap_attestation.c -fPIE -pie -o dcap_attestation -L "/opt/occlum/toolchains/dcap_lib/glibc" -locclum_dcap -I /opt/intel/sgxsdk/include -I "/opt/occlum/toolchains/dcap_lib/inc" -lssl -lcrypto

RUN sed -i 's|https://localhost:8081/sgx/certification/v4/|https://api.trustedservices.intel.com/sgx/certification/v4/|g' /etc/sgx_default_qcnl.conf

WORKDIR /app

EXPOSE 8080
ENTRYPOINT ["/usr/bin/supervisord"]
