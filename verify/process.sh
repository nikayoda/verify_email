#!/bin/bash
while true
do
        if ! pgrep php
          then
              /root/verify/run.sh
        fi
        sleep 1
done

