#!/bin/bash

systemctl stop demo-app

echo ${APPDIR}
cd ${APPDIR}
rm -rf ..?* .[!.]* *
