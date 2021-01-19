FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m babyheap
RUN chown -R root:root /home/babyheap
RUN chmod -R 755 /home/babyheap

CMD ["/usr/sbin/xinetd","-dontfork"]
