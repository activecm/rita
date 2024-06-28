# FROM alpine/git
# RUN git clone https://github.com/wolfcw/libfaketime /libfaketime \
#  && apk -U add build-base
# WORKDIR /libfaketime
# RUN make \
#  && make install

# # Library is in
# # - /usr/local/lib/faketime/libfaketimeMT.so.1
# # - /usr/local/lib/faketime/libfaketime.so.1

# # Build the final image
# FROM scratch as libfaketime
# COPY --from=0 /usr/local/lib/faketime/libfaketimeMT.so.1 /faketime.so

# FROM clickhouse/clickhouse-server:24.1.8-alpine as final
# ARG DEBIAN_FRONTEND=noninteractive
# COPY --from=libfaketime  /faketime.so /lib/faketime.so
# ENV LD_PRELOAD=/lib/faketime.so
# ENTRYPOINT ["/entrypoint.sh"]

FROM clickhouse/clickhouse-server:24.1.8
COPY  ./init_ch.sh /docker-entrypoint-initdb.d/init_ch.sh

# Install libfaketime
# RUN apt-get update && \
#     apt-get install -y libfaketime && \
#     rm -rf /var/lib/apt/lists/*

# # Set the environment variable to preload libfaketime
# RUN export LD_PRELOAD=/usr/lib/$(uname -m)-linux-gnu/faketime/libfaketime.so.1

# # You can set a default time offset or specific time
# ENV FAKETIME="-15d"

# # Optional: If you want all child processes to be affected
# ENV FAKETIME_DONT_RESET=1
# ENTRYPOINT [ "/bin/sh", "-c" ]
# CMD ["clickhouse-server"]