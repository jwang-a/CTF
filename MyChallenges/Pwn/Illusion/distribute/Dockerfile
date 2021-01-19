FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m Illusion
RUN chown -R root:root /home/Illusion
RUN chmod -R 755 /home/Illusion

CMD ["/usr/sbin/xinetd","-dontfork"]
