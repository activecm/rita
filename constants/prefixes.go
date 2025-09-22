package constants

// these zeek log prefixes are in their own constants package to avoid import cycles across the different packages that need it
// could maybe be refactored in the future
const ConnPrefix = "conn"
const OpenConnPrefix = "open_conn"
const DNSPrefix = "dns"
const HTTPPrefix = "http"
const OpenHTTPPrefix = "open_http"
const SSLPrefix = "ssl"
const OpenSSLPrefix = "open_ssl"
const ConnSummaryPrefixUnderscore = "conn_summary"
const ConnSummaryPrefixHyphen = "conn-summary"
