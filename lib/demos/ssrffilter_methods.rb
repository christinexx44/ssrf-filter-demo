require 'resolv'

DEFAULT_RESOLVER = proc do |hostname|
  ::Resolv.getaddresses(hostname).map { |ip| ::IPAddr.new(ip) }
end

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
