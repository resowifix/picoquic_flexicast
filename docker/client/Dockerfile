# ---------- Stage 1 : build ----------
FROM alpine:latest AS builder

RUN apk add --no-cache build-base cmake git pkgconf openssl-dev ca-certificates

WORKDIR /src

ARG BUILD_ARG=1
RUN git clone -b flexicast_dtgrm_server https://github.com/resowifix/picoquic_flexicast.git

WORKDIR /src/picoquic_flexicast
RUN cmake -DPICOQUIC_FETCH_PTLS=Y .
RUN make

# ---------- Stage 2 : runtime ----------
FROM alpine:latest

RUN apk add --no-cache openssl ca-certificates

WORKDIR /app
COPY --from=builder /src/picoquic_flexicast/picoquic_fc /app/picoquic_fc

ENV SERVER=127.0.0.1
ENV PORT=4433
ENV LOG_DIR=/app/log

ENTRYPOINT ["sh", "-c", "/app/picoquic_fc \"$SERVER\" \"$PORT\" \"$LOG_DIR\""]
