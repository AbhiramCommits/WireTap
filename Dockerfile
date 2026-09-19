# WireTap handler + archive image.
# Builds the C++ handler against Apache Arrow from the official apt repo.
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates wget \
    && cd /tmp \
    && wget -q "https://apache.jfrog.io/artifactory/arrow/ubuntu/apache-arrow-apt-source-latest-$(. /etc/os-release && echo $VERSION_CODENAME).deb" \
    && apt-get install -y --no-install-recommends ./apache-arrow-apt-source-latest-*.deb \
    && apt-get update && apt-get install -y --no-install-recommends \
    libarrow-dev libparquet-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/apache-arrow-apt-source-latest-*.deb

COPY . /src/wiretap
WORKDIR /src/wiretap
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DWIRETAP_BUILD_TESTS=OFF \
    && cmake --build build -j2

ENTRYPOINT ["./build/wiretap_recv"]
