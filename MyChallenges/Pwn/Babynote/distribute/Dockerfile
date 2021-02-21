FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m Babynote
RUN chown -R root:root /home/Babynote
RUN chmod -R 755 /home/Babynote

CMD ["/usr/sbin/xinetd","-dontfork"]
