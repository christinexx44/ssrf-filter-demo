require 'resolv'

def host_header(hostname, uri)
  # Attach port for non-default as per RFC2616
  if (uri.port == 80 && uri.scheme == 'http') ||
     (uri.port == 443 && uri.scheme == 'https')
    hostname
  else
    "#{hostname}:#{uri.port}"
  end
end

DEFAULT_RESOLVER = proc do |hostname|
  ::Resolv.getaddresses(hostname).map { |ip| ::IPAddr.new(ip) }
end
