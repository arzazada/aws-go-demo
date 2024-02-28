#!/bin/bash

systemctl stop demo-app

echo APPDIR=/etc/demo-app >> /etc/environment
echo ${APPDIR}
cd ${APPDIR}
rm -rf ..?* .[!.]* *
