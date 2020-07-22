# gdbchal by kuilin

FROM jaschac/debian-gcc:latest
RUN apt-get update && apt-get install -y socat gdb

COPY flag.txt /
RUN chmod 644 /flag.txt

RUN useradd pwn
USER pwn

EXPOSE 1234/tcp
CMD socat -vv tcp-listen:1234,reuseaddr,fork system:'gdb -ex "target\\\ remote\\\ /proc/self/fd/10" </dev/null >/dev/null 2>/dev/null',pty,fdin=10,fdout=10
