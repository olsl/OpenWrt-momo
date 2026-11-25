#!/bin/sh

# enable momo_server service
[ -x /etc/init.d/momo_server ] && /etc/init.d/momo_server enable

exit 0
