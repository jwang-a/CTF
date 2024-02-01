FROM ubuntu:20.04@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8
MAINTAINER James

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install open-cobol -qy
CMD /root/compile.sh
