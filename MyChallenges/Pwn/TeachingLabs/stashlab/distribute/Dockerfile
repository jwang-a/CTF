FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m stashlab
RUN chown -R root:root /home/stashlab
RUN chmod -R 755 /home/stashlab

CMD ["/usr/sbin/xinetd","-dontfork"]
