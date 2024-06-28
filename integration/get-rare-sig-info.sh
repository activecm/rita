#!/bin/bash

# this script is used to gather signature information from a tsv zeek log

# src: the source ip
# pair: optional destination ip or fqdn
# method: 'src' or 'pair' (use pair if you want to specify a destination ip or fqdn)
# directory: the directory where the logs are located

src='10.55.100.104' # '10.55.100.111'
# src='192.168.88.2'
# src='45.125.66.34'
# src='10.55.100.111'
# src='10.55.100.100'
pair='www.alexa.com'
# pair='52.44.164.170'
method='pair' # options: 'pair' or 'src'
directory=$(realpath ../test_data/valid_tsv)
directory="$directory/"

# set the field for the src ip in the logs
src_field='3' # src ip field for all log types (conn, http, ssl) is 3

# set default field for the pair (if specified, the destination ip or fqdn in the log)
conn_pair_field='5' # conn dst field
http_pair_field='9' # http host field (change to 5 if using dst ip as the pair)
ssl_pair_field='10' # ssl server_name field (change to 5 if using dst ip as the pair)

# set field for the dst ip in the logs
dst_ip_field='5' # dst ip field for all log types (conn, http, ssl) is 5

# set field for the fqdn in the logs
http_fqdn_field='9' # http host field
ssl_fqdn_field='10' # ssl server_name field

# set field for the signature field in the logs
http_sig_field='13' # http useragent field
ssl_sig_field='22' # ssl ja3 field

IFS=$'\n'  # set the internal field separator to newline

get_column() {
    if [ $method = 'src' ]; then
        awk -v src_field="$src_field" -v src="$src" -v column="$2" -F'\t' '($src_field == src) { print $column }' "$directory""$1".log
    elif [ $method = 'pair' ]; then
        awk -v src_field="$src_field" -v src="$src" -v pair_field="$3" -v pair="$4" -v column="$2" -F'\t' '($src_field == src) && ($pair_field == pair) { print $column }' "$directory""$1".log
    else
        echo "Invalid method. Please choose 'src' or 'pair'."        
    fi 
}

get_column_with_specific_sig() {
    if [ $method = 'src' ]; then
        awk -v src_field="$src_field" -v src="$src" -v column="$2" -v sig_field="$5" -v sig="$6" -F'\t' '($src_field == src) && ($sig_field == sig) { print $column }' "$directory""$1".log
    elif [ $method = 'pair' ]; then
        awk -v src_field="$src_field" -v src="$src" -v pair_field="$3" -v pair="$4" -v column="$2" -v sig_field="$5" -v sig="$6" -F'\t' '($src_field == src) && ($pair_field == pair) && ($sig_field == sig) { print $column }' "$directory""$1".log
    else
        echo "Invalid method. Please choose 'src' or 'pair'."        
    fi 
}

get_missing_host_useragents(){
    missing_host='-'
    awk -v src_field="$src_field" -v src="$src" -v pair_field="$http_fqdn_field" -v pair="$missing_host" -v column="$http_sig_field" -F'\t' '($src_field == src) && ($pair_field == pair) { print $column }' "$directory""http.log"
}

get_missing_host_useragents_all_srcs(){
    missing_host='-'
    awk -v pair_field="$http_fqdn_field" -v pair="$missing_host" -v column="$http_sig_field" -F'\t' '($pair_field == pair) { print $column }' "$directory""http.log"
}

# get the useragents 
unique_useragent_count=0
useragent_list=()
echo "-- Useragents:"
for useragent in $( get_column 'http' $http_sig_field $http_pair_field $pair | sort | uniq); do
    if [ "$useragent" != "-" ]; then

        # get unique dst ip count for the given useragent
        dst_ip_count=0
        for dst_ip in $( get_column_with_specific_sig 'http' $dst_ip_field $http_pair_field $pair $http_sig_field $useragent | sort | uniq); do
            if [ "$dst_ip" != "-" ]; then
                dst_ip_count=$((dst_ip_count + 1))
            fi
        done

        # get unique fqdn count for the given useragent
        fqdn_count=0
        for fqdn in $( get_column_with_specific_sig 'http' $http_fqdn_field $http_pair_field $pair $http_sig_field $useragent | sort | uniq); do
            if [ "$fqdn" != "-" ]; then
                fqdn_count=$((fqdn_count + 1))
            fi
        done

        echo "$useragent" #" ~~~~~~ times_used_dst: " "$dst_ip_count" " ~~~~~~ times_used_fqdn: " "$fqdn_count"
        unique_useragent_count=$((unique_useragent_count + 1))
    fi
done
echo "-- Unique Useragent Count: $unique_useragent_count"

# get the ja3 signatures
unique_ja3_count=0
ja3_list=()
echo "-- JA3:"
for ja3 in $( get_column 'ssl' $ssl_sig_field $ssl_pair_field $pair | sort | uniq); do
    if [ "$ja3" != "-" ]; then

        # get unique dst ip count for the given ja3
        dst_ip_count=0
        for dst_ip in $( get_column_with_specific_sig 'ssl' $dst_ip_field $ssl_pair_field $pair $ssl_sig_field $ja3 | sort | uniq); do
            if [ "$dst_ip" != "-" ]; then
                dst_ip_count=$((dst_ip_count + 1))
            fi
        done

        # get unique fqdn count for the given ja3
        fqdn_count=0
        for fqdn in $( get_column_with_specific_sig 'ssl' $ssl_fqdn_field $ssl_pair_field $pair $ssl_sig_field $ja3 | sort | uniq); do
            if [ "$fqdn" != "-" ]; then
                fqdn_count=$((fqdn_count + 1))
            fi
        done

        echo "$ja3" #" ~~~~~~ times_used_dst: " "$dst_ip_count" " ~~~~~~ times_used_fqdn: " "$fqdn_count"
        unique_ja3_count=$((unique_ja3_count + 1))
    fi
done
echo "-- Unique JA3 Count: $unique_ja3_count"

# get the missing_host_useragent signatures
unique_missing_host_useragent_count=0
# missing_host_useragent_list=()
echo "-- Missing Host Useragents For Source IP (pair value does not apply):"
for missing_host_useragent in $( get_missing_host_useragents | sort | uniq); do
    if [ "$missing_host_useragent" != "-" ]; then
        echo "$missing_host_useragent"
        unique_missing_host_useragent_count=$((unique_missing_host_useragent_count + 1))
    fi
done
echo "-- Unique Missing Host Useragent Count: $unique_missing_host_useragent_count"

# get the missing_host_useragent signatures for all srcs
unique_missing_host_useragent_count_all_srcs=0
# missing_host_useragent_list=()
echo "-- Missing Host Useragents For All Source IPs in Log :"
for missing_host_useragent in $( get_missing_host_useragents_all_srcs | sort | uniq); do
    if [ "$missing_host_useragent" != "-" ]; then
        echo "$missing_host_useragent"
        unique_missing_host_useragent_count_all_srcs=$((unique_missing_host_useragent_count_all_srcs + 1))
    fi
done
echo "-- Unique Missing Host Useragent Count For All Source IPs: $unique_missing_host_useragent_count_all_srcs"

unset IFS  # reset the internal field separator to default
