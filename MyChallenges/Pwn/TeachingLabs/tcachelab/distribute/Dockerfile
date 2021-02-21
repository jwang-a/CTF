FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m tcachelab
RUN chown -R root:root /home/tcachelab
RUN chmod -R 755 /home/tcachelab

CMD ["/usr/sbin/xinetd","-dontfork"]
