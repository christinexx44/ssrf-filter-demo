require "test_helper"

class TestMethodsInSsrfFilter < Minitest::Test
  DEFAULT_SCHEME_WHITELIST = %w[http https].freeze

  def test_getaddresses
      # ::Resolv.getaddress is called in DEFAULT_RESOLVER
      # getaddresses will return an array resolved by the given hostname
      # for the following domain name that may be resolved as "localhost",
      # .getaddress() will return an empty list
      # UnresolvedHostname will be raised here
      # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L124
      ["127.000.000.01", "0x7f", "008.08.8.8", \
      "2130706433", "017700000001", "3232235521","3232235777", "0x7f000001", "0xc0a80014" ].each do |host_name|
        assert 0, ::Resolv.getaddresses(host_name).length()
      end

      # [  "0.0.0.0", "0.0.0.0"].each do |host_name|
      #   puts ::Resolv.getaddresses(host_name)
      # end
  end

  # whitelist allows only http and https
  # scheme must be http or https, otherwise ssrf_fiter will raise an error
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L118
  def test_whitelist
    ["file:///etc/passwd", "file://\/\/etc/passwd" ].each do |url|
      uri = URI(url)
      assert "file", uri.scheme
      if DEFAULT_SCHEME_WHITELIST.include?(uri.scheme)
        assert false
      end
    end
    assert true
  end

  # used in self.unsafe_ip_address? (ip_address)
  # in ruby 3.2 (which is specified the README in remove-bg-web), include?
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L148
  # if unsafe_ip_address evaluates to true, the corresponding ip_address will be removed from the set

  # def include?(other)
  #   other = coerce_other(other)
  #   return false unless other.family == family
  #   range = to_range
  #   other = other.to_range
  #   range.begin <= other.begin && range.end >= other.end
  # end
  # alias === include?
  def test_include
    # test some IPV4 addrs
    # no mask: begin = end
    [::IPAddr.new("127.0.0.10"), ::IPAddr.new("0.0.0.0"), ::IPAddr.new("10.255.254.253") ].each do |ip_|
      assert ip_.to_s, ip_.to_range.begin.to_s
      assert ip_.to_s, ip_.to_range.end.to_s
    end

    assert ::IPAddr.new('0.0.0.0/8').to_range.begin.to_s == "0.0.0.0" and ::IPAddr.new('0.0.0.0/8').to_range.end.to_s == "0.255.255.255"
    assert ::IPAddr.new('169.254.0.0/16').to_range.begin.to_s == "169.254.0.0" and ::IPAddr.new('169.254.0.0/16').to_range.end.to_s == "169.254.255.255"

    # assert ::IPAddr.new('127.0.0.0/8').include?(::IPAddr.new("127.0.0.10"))
    # assert ::IPAddr.new("0.0.0.0/24").include?(::IPAddr.new("0.0.0.0"))
    # [::IPAddr.new('0.0.0.0/8'), # Current network (only valid as source address)
    # ::IPAddr.new('10.0.0.0/8'), # Private network
    # ::IPAddr.new('100.64.0.0/10'), # Shared Address Space
    # ::IPAddr.new('127.0.0.0/8'), # Loopback
    # ::IPAddr.new('169.254.0.0/16'), # Link-local
    # ::IPAddr.new('172.16.0.0/12'), # Private network
    # ::IPAddr.new('192.0.0.0/24'), # IETF Protocol Assignments
    # ::IPAddr.new('192.0.2.0/24') ].each do |ip_|
    #   puts ip_.instance_variable_get(:@mask_addr)
      # range_ = ip_.to_range
      # puts "["+range_.begin.to_s+", " + range_.end.to_s + "]"
    # end
    # test some IPV6 addrs
  end

  # creating a request based on the method is used in fetch_once within ssrf_filter.get
  # the response is processed by the block (:stream)
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L118
  # here just print the response of some urls
  # def test_request_unscreen
  #   ["https://static.remove.bg/uploader-examples/person/2.jpg"\
  #   , "https://static.remove.bg/uploader-examples/person/1.jpg"\
  #   , "https://static.remove.bg/uploader-examples/person/8.jpg"].each do |request_url|

  #     uri = URI(request_url)
  #     ip_addresses = DEFAULT_RESOLVER.call(uri.hostname).reject {|ipaddr| ipaddr.ipv6?}

  #     uri.hostname = ip_addresses.sample.to_s

  #     request = ::Net::HTTP::Get.new(uri)

  #     # host_header is private
  #     request['host'] = host_header(uri.hostname,  uri )

  #     image_extensions = {
  #       "image/jpeg" => "jpg",
  #       "image/png" => "png",
  #       "image/gif" => "gif",
  #     }

  #     content_type_passlist = image_extensions.keys

  #     request["User-Agent"] = "unscreen.com/1.0 video background remover"
  #     request["Accept"] = content_type_passlist.join(", ")

  #     http_options =   {
  #       open_timeout: 5,
  #       read_timeout: 5,
  #       write_timeout: 5,
  #       ssl_timeout: 5,
  #     }

  #     # http_options[:use_ssl] = (uri.scheme == 'https')
  #     # puts "----------#{uri.hostname}:#{uri.port}----------"

  #     ::Net::HTTP.start(uri.hostname, uri.port, http_options) do |http|
  #       # puts http.request(request)
  #     end

  #   end
  # end
end


# test on the ip address of remove.bg
# https://whatismyipaddress.com/hostname-ip
