#!/bin/bash
#set -e

echo "* Setting up /usr/src links from host"

for i in $(ls $SYSDIG_HOST_ROOT/usr/src)
do 
	ln -s $SYSDIG_HOST_ROOT/usr/src/$i /usr/src/$i
done

CONFIG_FILE=/opt/draios/etc/dragent.yaml

if [ ! -z "$ACCESS_KEY" ]; then
	echo "* Setting access key"
	
	if ! grep ^customerid $CONFIG_FILE > /dev/null 2>&1; then
		echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
	else
		sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$TAGS" ]; then
	echo "* Setting tags"

	if ! grep ^tags $CONFIG_FILE > /dev/null 2>&1; then
		echo "tags: $TAGS" >> $CONFIG_FILE
	else
		sed -i "s/^tags.*/tags: $TAGS/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$COLLECTOR" ]; then
	echo "* Setting collector endpoint"

	if ! grep ^collector $CONFIG_FILE > /dev/null 2>&1; then
		echo "collector: $COLLECTOR" >> $CONFIG_FILE
	else
		sed -i "s/^collector.*/collector: $COLLECTOR/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$SECURE" ]; then
	echo "* Setting connection security"

	if ! grep ^ssl $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl: $SECURE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl.*/ssl: $SECURE/g" $CONFIG_FILE
	fi
fi

if [ $# -eq 0 ]; then
	if ! /opt/draios/bin/sysdigcloud-probe-loader; then
		exit 1
	fi

	exec /opt/draios/bin/dragent
else
	exec "$@"
fi
