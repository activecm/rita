#!/opt/homebrew/bin/bash

# This script is used to gather data used in integration testing of the port_info table

# src: the source IP
# dst: the destination IP
# directory: the directory where the logs are located

directory=$(realpath ../test_data/valid_tsv)
directory="$directory/"

# src='10.55.100.111'
# dst='24.220.113.59'

# src='10.55.100.111'
# dst='162.208.22.39'

# src='10.55.100.103'
# dst='code.jquery.com'

# src='10.55.100.100'
# dst='fls.doubleclick.net'


# src='10.55.100.105'
# dst='au.download.windowsupdate.com'

# src='10.55.100.109'
# dst='7.dl.delivery.mp.microsoft.com'


# src='10.55.100.105'
# dst='g.live.com'

# src='10.55.100.107'
# dst='sp.adbrn.com'

# src='10.55.100.105'
# dst='192.132.33.27'

# src='10.55.200.10'
# dst='217.70.179.1'

# src='10.55.100.103'
# dst='47.89.68.213'

# src='10.55.100.111'
# dst='34.209.114.116'

# src='10.55.182.100'
# dst='96.45.33.73'

# # src='10.55.200.11'
# # dst='205.251.198.178'

# src='10.55.182.100'
# dst='172.217.8.206'

src='10.55.100.111'
dst='165.227.216.194'

method='ip' # options: 'ip' or 'fqdn'
# method='fqdn'

echo "Source: $src"
if [ "$method" = 'ip' ]; then
    echo "Destination: $dst"
elif [ "$method" = 'fqdn' ]; then
    echo "FQDN: $dst"
fi

echo "Method: $method"

# set default field for the destination ip or fqdn in the log
dst_field='5' # conn dst field
http_dst_field='9' # http host field
ssl_dst_field='10' # ssl server_name field

zeek_uid_field='2' # field for the zeek uid in all log types (conn, http, ssl)

# Set the field for the src IP in the logs
src_field='3' # src IP field for all log types (conn, http, ssl)

# Set the fields for the additional information in the logs
port_field='6'
proto_field='7'
service_field='8'
bytes_sent_field='18'
bytes_received_field='20'

# IFS=$'\n'  # Set the internal field separator to newline

get_column() {
    awk -v src_field="$src_field" -v dst_field="$dst_field" -v src="$src" -v dst="$dst" -v column="$1" -F'\t' '($src_field == src) && ($dst_field == dst) { print $column }' "$directory""$2".log
}

get_port_proto_services() {
    awk -v src_field="$src_field" -v dst_field="$dst_field" -v src="$src" -v dst="$dst" -v port_field="$port_field" -v proto_field="$proto_field" -v service_field="$service_field" -v bytes_sent_field="$bytes_sent_field" -v bytes_received_field="$bytes_received_field" -F'\t' '
    ($src_field == src) && ($dst_field == dst) { print $port_field ":" $proto_field ":" $service_field "\t" $bytes_sent_field "\t" $bytes_received_field }' "$directory""$1".log
}

get_zeek_uids() {
    awk -v src_field="$src_field" -v dst_field="$2" -v src="$src" -v dst="$dst" -v uid_field="$zeek_uid_field" -F'\t' '($src_field == src) && ($dst_field == dst) { print $uid_field }' "$directory""$1".log
} 

get_port_proto_services_by_uid() {
    awk -v src_field="$src_field" -v uid_field="$zeek_uid_field" -v src="$src" -v uid="$1" -v port_field="$port_field" -v proto_field="$proto_field" -v service_field="$service_field" -v bytes_sent_field="$bytes_sent_field" -v bytes_received_field="$bytes_received_field" -F'\t' '
    ($src_field == src) && ($uid_field == uid) { print $port_field ":" $proto_field ":" $service_field "\t" $bytes_sent_field "\t" $bytes_received_field }' "$directory""$2".log
}



# Declare an associative array to hold the bytes sent and received for each tuple
declare -A tuple_count
declare -A bytes_sent
declare -A bytes_received


# Function to process each log file
process_log_file() {
    local log_type="$1"
    while IFS=$'\t' read -r tuple sent received; do
        if [[ -n "$tuple" && -n "$sent" && -n "$received" ]]; then
            tuple_count["$tuple"]=$((tuple_count["$tuple"] + 1))
            bytes_sent["$tuple"]=$((bytes_sent["$tuple"] + sent))
            bytes_received["$tuple"]=$((bytes_received["$tuple"] + received))
        fi
    done < <(get_port_proto_services "$log_type")
}

process_log_file_by_uid() {
    # echo "Processing UID: $1"
    local uid="$1"
    local log_type="$2"
    while IFS=$'\t' read -r tuple sent received; do
        if [[ -n "$tuple" && -n "$sent" && -n "$received" ]]; then
            tuple_count["$tuple"]=$((tuple_count["$tuple"] + 1))
            bytes_sent["$tuple"]=$((bytes_sent["$tuple"] + sent))
            bytes_received["$tuple"]=$((bytes_received["$tuple"] + received))
        fi
    done < <(get_port_proto_services_by_uid "$uid" "$log_type")
}


if [ $method = 'ip' ]; then
    # Process conn.log
    process_log_file 'conn'
    # Process open_conn.log
    # process_log_file 'open_conn'
elif [ "$method" = 'fqdn' ]; then
    # Separate UIDs from http and ssl logs
    http_uids=()
    ssl_uids=()
    openhttp_uids=()
    openssl_uids=()

    # get UIDs from http.log
    while IFS= read -r uid; do
        http_uids+=("$uid")
    done < <(get_zeek_uids 'http' "$http_dst_field")
    # debug: print length of UIDs
    echo "Length of UIDs from http.log: ${#http_uids[@]}"

    # get UIDs from ssl.log
    while IFS= read -r uid; do
        ssl_uids+=("$uid")
    done < <(get_zeek_uids 'ssl' "$ssl_dst_field")
    # debug: print length of UIDs
    echo "Length of UIDs from ssl.log: ${#ssl_uids[@]}"

    # # get UIDs from open_http.log
    # while IFS= read -r uid; do
    #     openhttp_uids+=("$uid")
    # done < <(get_zeek_uids 'open_http' "$http_dst_field")
    # # debug: print length of UIDs
    # echo "Length of UIDs from open_http.log: ${#openhttp_uids[@]}"

    # # get UIDs from open_ssl.log
    # while IFS= read -r uid; do
    #     openssl_uids+=("$uid")
    # done < <(get_zeek_uids 'open_ssl' "$ssl_dst_field")
    # # debug: print length of UIDs
    # echo "Length of UIDs from open_ssl.log: ${#openssl_uids[@]}"

    # Merge and remove duplicate UIDs
    all_uids=("${http_uids[@]}" "${ssl_uids[@]}" ) # "${openhttp_uids[@]}" "${openssl_uids[@]}"
    unique_uids=($(printf "%s\n" "${all_uids[@]}" | sort | uniq))

    # print length of uids
    echo "Length of All UIDs: ${#all_uids[@]}"
    echo "Length of Unique UIDs: ${#unique_uids[@]}"

    # Process conn.log and open_conn.log for each UID
    for uid in "${unique_uids[@]}"; do
        # echo "Processing UID: $id"  # debug: Print the UID being processed
        process_log_file_by_uid "$uid" 'conn'
        # process_log_file_by_uid "$uid" 'open_conn'
    done

    # Process conn.log for each unique Zeek UID
    # for id in "${unique_uids[@]}"; do
    #     awk -v id="$id" -F'\t' '($2 == id) { print $0 }' "$directory""conn.log" | while IFS=$'\t' read -r line; do
    #         # Troubleshooting: print the entire matched line for the UID
    #         echo "Matching line for UID $id: $line"
    #     done
    # done
    
fi

# Output the unique tuples and their byte counts
for tuple in "${!bytes_sent[@]}"; do
    echo "Tuple: $tuple"
    echo "Count: ${tuple_count[$tuple]}"
    echo "Bytes Sent: ${bytes_sent[$tuple]}"
    echo "Bytes Received: ${bytes_received[$tuple]}"
    echo "----"
done
