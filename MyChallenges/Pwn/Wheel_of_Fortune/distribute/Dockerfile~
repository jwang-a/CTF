FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m WOF
RUN chown -R root:root /home/WOF
RUN chmod -R 755 /home/WOF

CMD ["/usr/sbin/xinetd","-dontfork"]
