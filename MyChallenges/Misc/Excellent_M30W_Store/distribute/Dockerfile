FROM python:3.8-buster
MAINTAINER James

RUN apt-get update
RUN apt-get install xinetd -y
RUN pip3 install --no-cache-dir openpyxl
RUN pip3 install --no-cache-dir xlcalculator

RUN useradd -m ExcellentM30WStore
RUN chown -R root:root /home/ExcellentM30WStore
RUN chmod -R 755 /home/ExcellentM30WStore

CMD ["/usr/sbin/xinetd","-dontfork"]
