#!/bin/bash

# this script is used to gather connection information on a unique conn, http or ssl pair from a tsv zeek log

# src: the source ip
# dst: the destination ip or fqdn
# type: the log type (conn, http, ssl)
# directory: the directory where the logs are located

src='192.168.88.2'  # '10.55.100.109'
dst='165.227.88.15' # 'www.alexa.com'
type='conn'
directory=$(realpath ../test_data/valid_tsv)
directory="$directory/"

# set default field for the destination ip or fqdn in the log
field='5' # conn dst field
if [ $type = 'http' ]; then field='9'; fi
if [ $type = 'ssl' ]; then field='10'; fi

total_src_bytes=0
total_dst_bytes=0
total_src_ip_bytes=0
total_dst_ip_bytes=0
total_ip_bytes=0
total_duration=0
total_src_packets=0
total_dst_packets=0
conn_count=0
ts_list_len=0
src_ip_bytes_list_len=0

get_conn_column() {
    awk -v src="$src" -v dst="$dst" -v dst_field="$field" -v column="$1" -F'\t' '($3 == src) && ($dst_field == dst) { print $column }' "$directory""$type".log
}

# get connection information for unique http or ssl pair by linking associated conn records via zeek uid
if [ $type = 'http' ] || [ $type = 'ssl' ]; then
    for id in $(awk -v src="$src" -v dst="$dst" -v dst_field="$field" -F'\t' '($3 == src) && ($dst_field == dst) { print $2 }' "$directory""$type".log | sort | uniq); do
        while read -r dur src_bytes dst_bytes src_packets src_ip_bytes dst_packets dst_ip_bytes; do
            if [ "$dur" != "-" ]; then total_duration=$(echo "$total_duration + $dur" | bc ); fi
            if [ "$src_bytes" != "-" ]; then total_src_bytes=$((total_src_bytes + src_bytes)); fi
            if [ "$dst_bytes" != "-" ]; then total_dst_bytes=$((total_dst_bytes + dst_bytes)); fi
            if [ "$src_ip_bytes" != "-" ]; then 
                total_src_ip_bytes=$((total_src_ip_bytes + src_ip_bytes))
                src_ip_bytes_list_len=$((src_ip_bytes_list_len + 1))
            fi
            if [ "$dst_ip_bytes" != "-" ]; then total_dst_ip_bytes=$((total_dst_ip_bytes + dst_ip_bytes)); fi
            if [ "$src_packets" != "-" ]; then total_src_packets=$((total_src_packets + src_packets)); fi
            if [ "$dst_packets" != "-" ]; then total_dst_packets=$((total_dst_packets + dst_packets)); fi
        done < <(awk -v id="$id" -F'\t' '($2 == id) { print $9,$10,$11,$17,$18,$19,$20 }' "$directory""conn.log")
        conn_count=$((conn_count + 1))
    done
fi


# get connection information for unique conn pair
if [ "$type" = 'conn' ]; then
    while read -r dur src_bytes dst_bytes src_packets src_ip_bytes dst_packets dst_ip_bytes; do
        if [ "$dur" != "-" ]; then total_duration=$(echo "$total_duration + $dur" | bc ); fi
        if [ "$src_bytes" != "-" ]; then total_src_bytes=$((total_src_bytes + src_bytes)); fi
        if [ "$dst_bytes" != "-" ]; then total_dst_bytes=$((total_dst_bytes + dst_bytes)); fi
        if [ "$src_ip_bytes" != "-" ]; then 
            total_src_ip_bytes=$((total_src_ip_bytes + src_ip_bytes))
            src_ip_bytes_list_len=$((src_ip_bytes_list_len + 1))
        fi
        if [ "$dst_ip_bytes" != "-" ]; then total_dst_ip_bytes=$((total_dst_ip_bytes + dst_ip_bytes)); fi
        if [ "$src_packets" != "-" ]; then total_src_packets=$((total_src_packets + src_packets)); fi
        if [ "$dst_packets" != "-" ]; then total_dst_packets=$((total_dst_packets + dst_packets)); fi
        conn_count=$((conn_count + 1))
    done < <(awk -v src="$src" -v dst="$dst" -v dst_field="$field" -F'\t' '($3 == src) && ($dst_field == dst) { print $9,$10,$11,$17,$18,$19,$20 }' "$directory""$type".log)
fi


# print connection information
echo "Source: $src"
if [ "$type" = 'conn' ]; then echo "DST: $dst"; else echo "FQDN: $dst"; fi
echo "Connection Count: $conn_count"
echo "Total Duration: $total_duration"
echo "Total Source Bytes: $total_src_bytes"
echo "Total Resp Bytes: $total_dst_bytes"
echo "Total Source IP Bytes: $total_src_ip_bytes"
echo "Total Resp IP Bytes: $total_dst_ip_bytes"
echo "Total IP Bytes: $(($total_src_ip_bytes + $total_dst_ip_bytes))"
echo "Total Source Packets: $total_src_packets"
echo "Total Resp Packets: $total_dst_packets"
echo "Length of Src IP Bytes List: $src_ip_bytes_list_len"

# get timestamps for when the connection was first and last seen
echo "First Seen: $( get_conn_column '1' | sort | head -n1)"
echo "Last Seen: $( get_conn_column '1' | sort | tail -n1)"

# get number of unique timestamps for connection
for entry in $( get_conn_column '1' | sort | uniq); do
    ts_list_len=$((ts_list_len + 1))
done
echo "Length of Unique TS List: $ts_list_len"


# get unique destination count for http and ssl logs
if [ "$type" = 'http' ] || [ "$type" = 'ssl' ]; then
    dst_count=0
    for entry in $( get_conn_column '5' | sort | uniq); do
        dst_count=$((dst_count + 1))
    done
    echo "Count of Unique Destinations: $dst_count"
fi

# if log type is http, get the useragents for given src-fqdn pair
if [ "$type" = 'http' ]; then
    IFS=$'\n'  # set the internal field separator to newline
    unique_useragent_count=0
    useragent_list=()
    for useragent in $( get_conn_column '13' | sort | uniq); do
        if [ "$useragent" != "-" ]; then
            useragent_list+=$useragent
            unique_useragent_count=$((unique_useragent_count + 1))
        fi
    done
    echo "Unique Useragent Count: $unique_useragent_count"
    # echo "Useragents: $useragent_list" # comment in if needed
    unset IFS  # reset the internal field separator to default
fi

# if log type is http, get the uris for the given src-fqdn pair
if [ "$type" = 'http' ]; then
    IFS=$'\n'  # set the internal field separator to newline
    unique_uri_count=0
    uri_list=()
    for uri in $( get_conn_column '10' | sort | uniq); do
        if [ "$uri" != "-" ]; then
            uri_list+="$uri"
            unique_uri_count=$((unique_uri_count + 1))
        fi
    done
    echo "Unique URI Count: $unique_uri_count"
    # echo "URIs: $uri_list" # comment in if needed
    unset IFS  # reset the internal field separator to default
fi

# get connection counts per hour
echo "Counts Per Hour:"
get_conn_column '1' | awk '{ input_epoch = $1; rounded_epoch = input_epoch - (input_epoch % 3600); print rounded_epoch}' | sort | uniq -c
