#!/bin/bash

###Cleanup
docker rm -f $(docker ps -aq)
chmod -R 777 ./tmp/dockerRoot/
chmod -R 777 ./tmp/instances/*
chmod 777 ./share/guest_home
rm -fr ./tmp/dockerRoot
rm -fr ./tmp/instances/*
rm -fr ./share/guest_home/*

###Copy target files into challenge directory
if [ "$1" = "original" ]
then
  ln ./challengeBin/sentinel ./share/guest_home/sentinel
  ln ./challengeFlag/flag ./share/guest_home/flag
elif [ "$1" = "revenge" ]
then
  ln ./challengeBin/sentinelRevenge ./share/guest_home/sentinel
  ln ./challengeFlag/flagRevenge ./share/guest_home/flag
else
  echo "invalid target"
  exit
fi

ln ./challengeFlag/fakeFlag ./share/guest_home/fakeFlag

###Set permission of all files to prevent changes
chmod 777 ./tmp/instances
chmod 777 ./share/guest_home/flag
chmod 777 ./share/guest_home/fakeFlag
chmod 555 ./share/guest_home/sentinel
chmod 555 ./share/guest_home/

###Start service
docker-compose build
docker-compose up -d
