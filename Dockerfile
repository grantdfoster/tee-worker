ARG egover=1.6.0
ARG baseimage=ghcr.io/edgelesssys/ego-deploy:v${egover}
ARG VERSION

# Build the Go binary in a separate stage utilizing Makefile
FROM ghcr.io/edgelesssys/ego-dev:v${egover} AS dependencies

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Patch the main.go file to bypass worker ID check for testing
RUN sed -i 's/if err := tee.InitializeWorkerID(dataDir); err != nil {/tee.WorkerID = "hardcoded-worker-id"; if false \&\& err := tee.InitializeWorkerID(dataDir); err != nil {/' cmd/tee-worker/main.go

# Build the Go binary in a separate stage utilizing Makefile
FROM dependencies AS builder

ENV VERSION=${VERSION}
# Make an empty DISTRIBUTOR_PUBKEY to prevent validation errors
ARG DISTRIBUTOR_PUBKEY=""
# Set GO_TEST for tests to correctly handle TEE operations
ENV GO_TEST=true
RUN DISTRIBUTOR_PUBKEY=${DISTRIBUTOR_PUBKEY} make build

# Create a dummy certificate if one doesn't exist
RUN mkdir -p /app/tee && openssl genrsa -out /app/tee/private.pem -3 3072
RUN make ci-sign

RUN make bundle

# Use the official Ubuntu 22.04 image as a base for the final image
FROM ${baseimage} AS base
ARG pccs_server=https://pccs.dev.masalabs.ai

# Install Intel SGX DCAP driver
RUN apt-get update && \
    apt-get install -y lsb-core && \
    mkdir -p /etc/apt/keyrings && \
    wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl
RUN sed -i 's#"pccs_url": *"[^"]*"#"pccs_url": "'${pccs_server}'/sgx/certification/v4/"#' /etc/sgx_default_qcnl.conf
RUN sed -i 's#"use_secure_cert": true#"use_secure_cert": false#' /etc/sgx_default_qcnl.conf

COPY --from=builder /app/bin/masa-tee-worker /usr/bin/masa-tee-worker

# Create the 'masa' user and set up the home directory
RUN useradd -m -s /bin/bash masa && mkdir -p /home/masa && chown -R masa:masa /home/masa

# Create a dummy worker ID to bypass validation
RUN echo "dummy-worker-id" > /home/masa/worker_id && chown masa:masa /home/masa/worker_id

WORKDIR /home/masa
ENV DATA_DIR=/home/masa

# Set environment variables for simulation mode
ENV OE_SIMULATION=1
ENV STANDALONE=true
ENV SKIP_VALIDATION=true
ENV LOG_LEVEL=debug
ENV TWITTER_SKIP_LOGIN_VERIFICATION=true

# Expose necessary ports
EXPOSE 8080

# Set default command to start the Go application with enclave checks disabled
CMD ego run --simulate /usr/bin/masa-tee-worker
