#!/opt/homebrew/bin/bash

# This script is used to gather data used in integration testing of the tls_proto and http_proto tables

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

# src='10.55.100.110'	
# fqdn='static-ssl.businessinsider.com'

# src='10.55.100.104'
# fqdn='cdn.taboola.com'

# src='10.55.100.105'
# fqdn='www.alexa.com'

# 10.55.100.109	imasdk.googleapis.com
# src='10.55.100.109'
# fqdn='imasdk.googleapis.com'

src='10.55.100.107'
fqdn='ctldl.windowsupdate.com'

# src='10.55.100.107'
# fqdn='www.google.com'

# src='10.55.100.111'
# fqdn='ml314.com'

# src='10.55.100.110'
# fqdn='fe2.update.microsoft.com'

# src='10.55.100.108'
# fqdn='www.alexa.com'

# src='10.55.100.106'
# fqdn='settings-win.data.microsoft.com'

# src='10.55.100.109'
# fqdn='pixel.adsafeprotected.com'

# src='10.55.100.100'
# fqdn='oneclient.sfx.ms'

# src='10.55.100.107'
# fqdn='comet.yahoo.com'

# src='10.55.100.107'
# fqdn='www.googletagmanager.com'

# src='10.55.100.110'
# fqdn='www.facebook.com'

# method='tls' # options: 'tls' or 'http'
method='http'

echo "----"
echo "Source: $src"
echo "FQDN: $fqdn"
echo "Method: $method"
echo "----"

# set default field for the destination ip or fqdn in the log
# set field for the fqdn in the logs
fqdn_field='9' # http host field
if [ "$method" = 'tls' ]; then 
    fqdn_field='10'
fi

zeek_uid_field='2' # field for the zeek uid in all log types (conn, http, ssl)

# Set the field for the src IP in the logs
src_field='3' # src IP field for all log types (conn, http, ssl)

# Set the fields for the additional information in the logs
port_field='6'
proto_field='7'

# set field for the signature field in the logs
http_sig_field='13' # http useragent field
ssl_sig_field='22' # ssl ja3 field

# set ssl-specific fields
validation_status_field='21'
version_field='7'

# set http-specific fields
method_field='8'
uri_field='10'
referrer_field='11'
dst_mime_type_field='29'

# IFS=$'\n'  # Set the internal field separator to newline


get_tls_info() {
    awk -v src_field="$src_field" -v fqdn_field="$fqdn_field" -v src="$src" -v fqdn="$fqdn" -v ssl_sig_field="$ssl_sig_field" -v version_field="$version_field" -v validation_status_field="$validation_status_field" -F'\t' '
    ($src_field == src) && ($fqdn_field == fqdn) { print $ssl_sig_field ":" $version_field ":" $validation_status_field }' "$directory""$1".log
}

get_http_info(){
    awk -v src_field="$src_field" -v fqdn_field="$fqdn_field" -v src="$src" -v fqdn="$fqdn" -v http_sig_field="$http_sig_field" -v method_field="$method_field" -v uri_field="$uri_field" -v referrer_field="$referrer_field" -v dst_mime_type_field="$dst_mime_type_field" -F'\t' '
    ($src_field == src) && ($fqdn_field == fqdn) { print $http_sig_field " -- method: " $method_field " -- uri: " $uri_field " -- referrer: " $referrer_field "\t" $dst_mime_type_field }' "$directory""$1".log

}


declare -A count
declare -A mime_types

# Function to process each log file
process_tls_file() {
    local log_type="$1"
    while IFS=$'\t' read -r tuple; do
        if [[ -n "$tuple" ]]; then
            count["$tuple"]=$((count["$tuple"] + 1))
        fi
    done < <(get_tls_info "$log_type")
}

process_http_file() {
    local log_type="$1"
    while IFS=$'\t' read -r tuple dst_mime_type; do
        if [[ -n "$tuple" ]]; then
            count["$tuple"]=$((count["$tuple"] + 1))
            if [[ "$dst_mime_type" != "-" ]]; then
                mime_types["$tuple,$dst_mime_type"]=1
            fi
        fi
    done < <(get_http_info "$log_type")
}

# add unique mime type to the array
add_unique_mime_type() {
    local tuple="$1"
    local mime_type="$2"
    if [[ ! ",${mime_types[$tuple]}," == *",$mime_type,"* ]]; then
        add_unique_mime_type "$tuple" "$dst_mime_type"
    fi
}

if [ $method = 'tls' ]; then
    process_tls_file 'ssl' # ssl.log
    # process_tls_file 'open_ssl' # open_ssl.log
elif [ "$method" = 'http' ]; then
    process_http_file 'http' # http.log
    # process_http_file 'open_http' # open_http.log
fi

# Output the unique tuples and their byte counts
for tuple in "${!count[@]}"; do
    echo "$tuple"
    echo "Count: ${count[$tuple]}"
    if [ $method = 'http' ]; then
        # collect unique MIME types for this tuple
        unique_mime_types=()
        for key in "${!mime_types[@]}"; do
            if [[ $key == "$tuple,"* ]]; then
                mime_type="${key#*,}"
                unique_mime_types+=("$mime_type")
            fi
        done
        echo "Unique MIME Types: ${unique_mime_types[@]}"
    fi
    echo "----"
done
