#!/bin/bash

function get_nss_path()
{
    local profile=$1
    local firefox_root=$2
    
    [ -z "$firefox_root" ] && firefox_root="$HOME/.mozilla/firefox"

    db_path=""
    default=""
    while read line; do
	sec=`echo $line | awk ' $0 ~ /^\[.*\]/ {print $0; next} {print ""}'`
	if [ "$sec" ]; then
	    section=`echo $sec | sed 's/^\[\(.*\)\]$/\1/'`
	    db_path=""
	    default=""
	    continue
	fi
	[ -z "$section" ] && continue

	IFS='=' read key value <<< "$line"
	[ -z "$key" ] && continue

	case $key in
	    "Path")
		db_path=$value
		;;
	    "Default")
		[ $value -eq 1 ] && default="yes"
		;;
	    "Name")
		name="$value"
		;;
	esac
#	echo "read: $key = $value" >&2

	if [ "$db_path" ]; then
	    done=""
	    if [ "$profile" ]; then
		[ "$profile" = "$name" ] && done="yes"
	    else
		[ "$default" = "yes" ] && done="yes"
		[ "$name" = "default" ] && done="yes"
	    fi

	    if [ "$done" = "yes" ]; then
		echo $firefox_root/$db_path
		return
	    fi
	fi

    done < $firefox_root/profiles.ini

    echo ""
}

pkcs11_name=$1
pkcs11_path=$2

if [ -z "$pkcs11_name" -o -z "$pkcs11_path" ]; then
    name=`basename $0` 
    echo "$name <module_name> <module_path>"
    exit 1
fi

nss_path=$(get_nss_path)
if [ -z "$nss_path" ]; then
    echo "Failed to locate Firefox keystore"
    exit 1
fi

modutil -add "$pkcs11_name" -libfile "$pkcs11_path" -dbdir "$nss_path"
