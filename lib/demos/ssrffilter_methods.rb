require 'resolv'
require 'ssrf_filter'

IPV4_blacklist_ssrf = SsrfFilter.const_get :IPV4_BLACKLIST
IPV6_blacklist_ssrf = SsrfFilter.const_get :IPV6_BLACKLIST
DEFAULT_RESOLVER =  SsrfFilter.const_get :DEFAULT_RESOLVER
DEFAULT_SCHEME_WHITELIST =  SsrfFilter.const_get :DEFAULT_SCHEME_WHITELIST


# the methods are private in SsrfFilter, so I just copied them here
def host_header(hostname, uri)
  # Attach port for non-default as per RFC2616
  if (uri.port == 80 && uri.scheme == 'http') ||
     (uri.port == 443 && uri.scheme == 'https')
    hostname
  else
    "#{hostname}:#{uri.port}"
  end
end

def ipaddr_has_mask?(ipaddr)
  range = ipaddr.to_range
  range.first != range.last
end
