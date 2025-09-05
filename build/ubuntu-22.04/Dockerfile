FROM --platform=linux/amd64 ubuntu:22.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update

RUN apt-get install -y wget gnupg
RUN apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ jammy stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.7.0

RUN apt-get install -y build-essential cmake file
RUN echo -n "UBU2204" > /OSRELEASE.txt

RUN apt-get install -y curl libjsoncpp-dev

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://github.com/curl/curl/releases/download/curl-8_14_1/curl-8.14.1.tar.gz \
    && echo "6766ada7101d292b42b8b15681120acd68effa4a9660935853cf6d61f0d984d4 curl-8.14.1.tar.gz" | sha256sum -c \
    && tar -zxvf curl-8.14.1.tar.gz && cd curl-8.14.1 \
    && ./configure --enable-versioned-symbols --without-ssl --disable-ldap --with-nghttp2 --without-libpsl --disable-docs --disable-manual \
    && make && make install
RUN rm -rf /tmp/halon

COPY build.sh /build.sh
CMD ["/build.sh"]
