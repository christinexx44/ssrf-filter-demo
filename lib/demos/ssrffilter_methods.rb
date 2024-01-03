require 'resolv'
require 'ssrf_filter'

IPV4_blacklist_ssrf = SsrfFilter.const_get :IPV4_BLACKLIST
IPV6_blacklist_ssrf = SsrfFilter.const_get :IPV6_BLACKLIST
DEFAULT_RESOLVER =  SsrfFilter.const_get :DEFAULT_RESOLVER
DEFAULT_SCHEME_WHITELIST =  SsrfFilter.const_get :DEFAULT_SCHEME_WHITELIST
FIBER_LOCAL_KEY = :__ssrf_filter_hostname

VERB_MAP = SsrfFilter.const_get :VERB_MAP

# the methods are private in SsrfFilter, so I just moved them here
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

def with_forced_hostname(hostname, &_block)
  ::Thread.current[FIBER_LOCAL_KEY] = hostname
  yield
ensure
  ::Thread.current[FIBER_LOCAL_KEY] = nil
end

def fetch_once(uri, ip, verb, options, &block)
  ::SsrfFilter::Patch::SSLSocket.apply!

  if options[:params]
    params = uri.query ? ::Hash[::URI.decode_www_form(uri.query)] : {}
    params.merge!(options[:params])
    uri.query = ::URI.encode_www_form(params)
  end

  hostname = uri.hostname
  uri.hostname = ip

  request = VERB_MAP[verb].new(uri)
  request['host'] = host_header(hostname, uri)

  Array(options[:headers]).each do |header, value|
    request[header] = value
  end

  request.body = options[:body] if options[:body]

  block.call(request) if block_given?
  # validate_request(request)

  http_options = options[:http_options] || {}
  http_options[:use_ssl] = (uri.scheme == 'https')

  with_forced_hostname(hostname) do
    ::Net::HTTP.start(uri.hostname, uri.port, http_options) do |http|
      if options.key?(:stream)
        # for unscreen: should go here
        http.request(request) do |response|
          options[:stream].call(response) unless response.is_a?(Net::HTTPRedirection)
        end
      else
        # for remove-bg-web
        http.request(request)
      end
    end
  end
end
