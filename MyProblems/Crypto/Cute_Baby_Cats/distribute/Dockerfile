FROM python:3.8-buster
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -y
RUN pip3 install --no-cache-dir pycryptodome

RUN useradd -m CuteBabyCats
RUN chown -R root:root /home/CuteBabyCats
RUN chmod -R 755 /home/CuteBabyCats

CMD ["/usr/sbin/xinetd","-dontfork"]
