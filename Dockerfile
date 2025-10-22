FROM occlum/occlum:latest-ubuntu22.04
LABEL authors="Vencel Bajnok"
LABEL maintainer="bajnokvencel@edu.bme.hu"
LABEL description="Docker image for running the CMCaaS server on an Intel SGX enabled hardware using Occlum."
LABEL version="1.0.0"

# Install necessary packages
RUN apt-get update && apt-get install -y openjdk-21-jdk maven jq supervisor  && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the application source code
COPY src/enclave /app/src/enclave/
COPY src/server /app/src/server/
COPY scripts/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY scripts /app/scripts/
RUN chmod +x /app/scripts/*
COPY src/server/pom.xml app/src/server/

# Build the application
RUN cd app/src/server && mvn clean package

# Initialize Occlum environment
RUN occlum-javac src/enclave/VerifierRunner.java -d /app/src/enclave/

WORKDIR /app

EXPOSE 8080
ENTRYPOINT ["/usr/bin/supervisord"]
