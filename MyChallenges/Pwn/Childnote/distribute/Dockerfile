FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m Childnote
RUN chown -R root:root /home/Childnote
RUN chmod -R 755 /home/Childnote

CMD ["/usr/sbin/xinetd","-dontfork"]
