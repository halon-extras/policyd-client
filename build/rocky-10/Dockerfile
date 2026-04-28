FROM rockylinux/rockylinux:10.1
LABEL org.opencontainers.image.authors="support@halon.io"

ARG TARGETARCH
ARG TARGETOS

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN dnf update -y && dnf install -y epel-release

RUN echo "[halon]" >> /etc/yum.repos.d/Halon.repo
RUN echo "name=Halon repository" >> /etc/yum.repos.d/Halon.repo
RUN echo "baseurl=https://${HALON_REPO_USER}:${HALON_REPO_PASS}@repo.halon.io/dists/rhel10/${TARGETARCH}/stable" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgkey=https://raw.githubusercontent.com/halon/pgp-keys/master/pgp-keys/7F0A73B5.asc" >> /etc/yum.repos.d/Halon.repo
RUN echo "enabled=1" >> /etc/yum.repos.d/Halon.repo
RUN dnf install -y halon-6.11.0

RUN dnf install -y cmake make gcc-c++ rpm-build autoconf openssl-devel
RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://github.com/curl/curl/releases/download/curl-8_14_1/curl-8.14.1.tar.gz \
    && echo "6766ada7101d292b42b8b15681120acd68effa4a9660935853cf6d61f0d984d4 curl-8.14.1.tar.gz" | sha256sum -c \
    && tar -zxvf curl-8.14.1.tar.gz && cd curl-8.14.1 \
    && LD_LIBRARY_PATH=/usr/local/lib64 ./configure --without-libpsl --without-ssl --without-ldap \
    && make && make install
RUN rm -rf /tmp/halon
RUN dnf install -y jsoncpp-devel

RUN echo -n "ROCKY10" > /OSRELEASE.txt

COPY build.sh /build.sh
CMD ["/build.sh"]
