#!/opt/homebrew/bin/bash

# Set the source IP and FQDN for testing
# src='10.55.100.108'
# fqdn='www.businessinsider.com'

# src='10.55.100.107'
# fqdn='static.adsafeprotected.com'	

src='10.55.100.103'
fqdn='ml314.com'


# src='10.55.100.104'
# fqdn='a.scorecardresearch.com'

# src='10.55.100.106'
# fqdn='www.alexa.com'

# src='10.55.100.105'
# fqdn='static1.businessinsider.com'

directory=$(realpath ../test_data/valid_tsv)
directory="$directory/"

valid_mime_types_file=$(realpath ../deployment/http_extensions_list.csv)

echo "------------------------------"
echo "Source: $src"
echo "FQDN: $fqdn"
# echo "Log Directory: $directory"
# echo "Valid MIME Types File: $valid_mime_types_file"
echo "------------------------------"

# set default field for the destination ip or fqdn in the log
fqdn_field='9' # http host field
zeek_uid_field='2' # field for the zeek uid in all log types (conn, http, ssl)
src_field='3' # src IP field for all log types (conn, http, ssl)

# set log fields
port_field='6'
proto_field='7'
http_sig_field='13' # http useragent field
method_field='8'
uri_field='10'
referrer_field='11'
dst_mime_type_field='29'
ts_field='1'
import_time_field='4'

declare -A valid_mime_types
declare -A count
declare -A mismatch_count
declare -A mismatch_details


while IFS= read -r line; do
    mime_type=$(echo "$line" | csvcut -c 2)
    extension=$(echo "$line" | csvcut -c 3)

    # Remove quotes from mime_type and extension fields
    mime_type=$(echo "$mime_type" | tr -d '"')
    extension=$(echo "$extension" | tr -d '"')

    if [[ -z "$mime_type" ]]; then
        continue
    fi
    if [[ "$extension" == "none" ]]; then
        extension=""
    fi

    # Handle multiple extensions
    IFS=',' read -ra ext_array <<< "$extension"
    for ext in "${ext_array[@]}"; do
        ext=$(echo "$ext" | tr -d '.' | xargs) # Remove dots and trim whitespace
        if [[ -n "$ext" ]]; then
            valid_mime_types["$mime_type"]+="$ext,"
        fi
    done
done < "$valid_mime_types_file"

# debug output to check the valid MIME types
# for key in "${!valid_mime_types[@]}"; do
#     echo "Key: $key, Value: ${valid_mime_types[$key]}"
# done
# echo "------------------------------"


get_http_info(){
    awk -v src_field="$src_field" -v fqdn_field="$fqdn_field" -v src="$src" -v fqdn="$fqdn" -v uri_field="$uri_field" -v dst_mime_type_field="$dst_mime_type_field" -F'\t' '
    ($src_field == src) && ($fqdn_field == fqdn) { print $uri_field "\t" $dst_mime_type_field }' "$directory""$1".log

}


get_extension() {
    local path="$1"
    # Remove the query string if present
    path="${path%%\?*}"
    # Check if the path does not contain a . or ends with a .
    if [[ "$path" != *.* || "$path" == *"." ]]; then
        echo ""
    else
        # Split the last segment by . and take the last element as the extension
        echo "${path##*.}"
    fi
}

process_http_file() {
    local log_type="$1"
    while IFS=$'\t' read -r uri dst_mime_types; do
        if [[ -n "$uri" && "$uri" != '/' ]]; then

            # extract the path from the URI, ignoring the query string
            path=$(echo "$uri" | awk -F'?' '{print $1}')

            # get the extension from the path
            extension=$(get_extension "$path")

            # echo "uri: $uri"
            # echo "Path: $path"
            # echo "Extension: $extension"

            # check for mismatches for each MIME type in the array
            IFS=',' read -ra mime_types_array <<< "$dst_mime_types"
            for dst_mime_type in "${mime_types_array[@]}"; do
                dst_mime_type=$(echo "$dst_mime_type" | xargs) # trim whitespace
                if [[ -n "$dst_mime_type" ]]; then
                    valid_extensions="${valid_mime_types[$dst_mime_type]}"
                    if [[ -n "$valid_extensions" ]]; then
                        IFS=',' read -ra ext_array <<< "$valid_extensions"
                        if ! [[ " ${ext_array[@]} " =~ " ${extension} " ]]; then
                            key="$uri|$path|$extension|$dst_mime_type"
                            mismatch_count["$key"]=$((mismatch_count["$key"] + 1))
                            if [[ -z "$extension" ]]; then
                                mismatch_details["$key"]="URI: $uri\nPath: $path\nExtension: -\n"
                            else
                                mismatch_details["$key"]="URI: $uri\nPath: $path\nExtension: $extension\n"
                            fi
                            mismatch_details["$key"]+="dst_mime_type: $dst_mime_type\n"
                            mismatch_details["$key"]+="valid extensions: ${valid_extensions}\n"
                        fi
                    fi
                fi
            done
        fi
    done < <(get_http_info "$log_type")
}


# run the process
process_http_file "http"


# print the results
echo "Mismatch details and counts:"
echo "------------------------------"
for key in "${!mismatch_count[@]}"; do
    echo -e "${mismatch_details[$key]}"
    echo "Mismatch count: ${mismatch_count[$key]}"
    echo "----"
done

