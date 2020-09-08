FROM ubuntu:artful-20180706
MAINTAINER James

RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qy xinetd

COPY libc-2.26.so /lib/x86_64-linux-gnu/libc-2.26.so
COPY ld-2.26.so /lib64/ld-2.26.so

RUN useradd -m Oldnote
RUN chown -R root:root /home/Oldnote
RUN chmod -R 755 /home/Oldnote
ADD xinetd /etc/xinetd.d/oldnote

CMD ["/usr/sbin/xinetd","-dontfork"]
