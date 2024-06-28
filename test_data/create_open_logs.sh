# directory to copy logs from
valid_data=./valid_tsv/
# directory for new logs
open_data=./open_conns

# create open conns
cat $valid_data/conn.log | head -n28 > $open_data/open/open_conn.log
# close open conns
cat $valid_data/conn.log | head -n28 > $open_data/closed/conn.log
# create header for closed conns for open import
cat $valid_data/conn.log | head -n8 > $open_data/open/conn.log


# create open http
cat $valid_data/http.log | head -n28 > $open_data/open/open_http.log
# close open http conns
cat $valid_data/http.log | head -n28 > $open_data/closed/http.log
# create header for closed http conns for open import
cat $valid_data/http.log | head -n8 > $open_data/open/http.log
# add closed http conns for open import, use end of file so that they don't overlap with open zeek uids
cat $valid_data/http.log | tail -n11 >> $open_data/open/http.log

# create open ssl
cat $valid_data/ssl.log | head -n28 > $open_data/open/open_ssl.log
# close open ssl conns
cat $valid_data/ssl.log | head -n28 > $open_data/closed/ssl.log
# create header for closed ssl conns for open import
cat $valid_data/ssl.log | head -n8 > $open_data/open/ssl.log
# add closed ssl conns for open import, use end of file so that they don't overlap with open zeek uids
cat $valid_data/ssl.log | tail -n11 >> $open_data/open/ssl.log


# copy matching conn log entries over to closed conn log in open import for closed http conns
grep "^[^#;]" $open_data/open/http.log | awk '{ print $2 }' | sort | uniq | sort -nr | while read -r uid rest; do
    cat $valid_data/conn.log | grep $uid >> $open_data/open/conn.log 
done

# copy matching conn log entries over to closed conn log in open import for closed ssl conns
grep "^[^#;]" $open_data/open/ssl.log | awk '{ print $2 }' | sort | uniq | sort -nr | while read -r uid rest; do
    cat $valid_data/conn.log | grep $uid >> $open_data/open/conn.log 
done

# add closed conns for open import
cat $valid_data/conn.log | tail -n11 >> $open_data/open/conn.log


# copy matching conn log entries over to closed conn log in closed import & open conn log in open import for http conns
grep "^[^#;]" $open_data/open/open_http.log | awk '{ print $2 }' | sort | uniq | sort -nr | while read -r uid rest; do
    cat $valid_data/conn.log | grep $uid | tee -a $open_data/closed/conn.log >> $open_data/open/open_conn.log
done

# copy matching conn log entries over to closed conn log in closed import & open conn log in open import for ssl conns
grep "^[^#;]" $open_data/open/open_ssl.log | awk '{ print $2 }' | sort | uniq | sort -nr | while read -r uid rest; do
    cat $valid_data/conn.log | grep $uid | tee -a $open_data/closed/conn.log >> $open_data/open/open_conn.log
done



