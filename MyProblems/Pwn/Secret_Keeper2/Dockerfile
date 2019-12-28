FROM ubuntu:19.04

RUN apt-get update
RUN apt-get dist-upgrade -y
RUN apt-get install socat -y

COPY libc64_2.29.so /lib/x86_64-linux-gnu/libc-2.29.so
COPY ld64_2.29.so /lib64/ld-linux-x86-64.so.2

RUN useradd -m secret
COPY secret_keeper flag /home/secret/
RUN chown -R root:secret /home/secret
RUN chmod -R 750 /home/secret/
EXPOSE 4444
USER secret
CMD socat -T30 TCP-LISTEN:4444,reuseaddr,fork EXEC:/home/secret/secret_keeper 
