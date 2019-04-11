FROM ubuntu:latest
MAINTAINER Nika Revazishvili <nika@revazishvili.com>


# Working user
USER root

# APT update
RUN apt-get update

# Install and Test PHP
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys E1DD270288B4E6030699E45FA1715D88E1DF1F24
RUN echo 'deb http://ppa.launchpad.net/git-core/ppa/ubuntu trusty main' > /etc/apt/sources.list.d/git.list
RUN apt-get install --no-install-recommends -y \
    php-cli php-mysql git php-pgsql && php -m

# Cleaning directories
RUN apt-get -y autoremove && apt-get clean && apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Adding directory
WORKDIR /root

# Create directory
COPY . /root/

# Changing permissions
RUN chmod +x verify/process.sh && chmod +x verify/run.sh

# SMTP PORTS

EXPOSE 25
EXPOSE 587
EXPOSE 465

# Setting up entry point
#ENTRYPOINT verify/process.sh
ENTRYPOINT /bin/bash
