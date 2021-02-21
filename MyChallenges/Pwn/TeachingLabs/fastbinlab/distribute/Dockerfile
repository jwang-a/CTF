FROM ubuntu:focal
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -qy
RUN useradd -m fastbinlab
RUN chown -R root:root /home/fastbinlab
RUN chmod -R 755 /home/fastbinlab

CMD ["/usr/sbin/xinetd","-dontfork"]
