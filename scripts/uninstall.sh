#!/bin/bash

systemctl stop demo-app

cd ${APPDIR}
rm -rf ..?* .[!.]* *
