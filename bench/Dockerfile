# Bench/profile image: handler image + python3 + perf.
FROM wiretap-handler

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["bash"]
