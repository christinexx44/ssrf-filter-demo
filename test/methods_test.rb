require "test_helper"

class TestMethodsInSsrfFilter < Minitest::Test
  # ::Resolv.getaddress is called in DEFAULT_RESOLVER
  # getaddresses will return an array resolved by the given hostname
  # for the following domain name that may be resolved as "localhost",
  # .getaddresses) will return an empty list
  # UnresolvedHostname will be raised here
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L124
  def test_getaddresses
      ["127.000.000.01", "0x7f", "008.08.8.8", \
      "2130706433", "017700000001", "3232235521","3232235777", "0x7f000001", "0xc0a80014", "[::ffff:127.0.0.1]",\
       "[0:0:0:0:0:ffff:127.0.0.1]" ].each do |host_name|
        assert 0, ::Resolv.getaddresses(host_name).length()
      end
  end

  # IP that has mask is rejected (when range.begin != range.end)
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L155
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L146
  def test_IP_mask
    assert ::IPAddr.new('0.0.0.0/8').instance_variable_get(:@mask_addr).to_s(16) == "ff000000"
    assert ::IPAddr.new('0.0.0.0/8').to_range.begin.to_s == "0.0.0.0" \
    and ::IPAddr.new('0.0.0.0/8').to_range.end.to_s == "0.255.255.255"
    assert ipaddr_has_mask?(::IPAddr.new('0.0.0.0/8'))

    assert ::IPAddr.new('169.254.0.0/16').instance_variable_get(:@mask_addr).to_s(16) == "ffff0000"
    assert ::IPAddr.new('169.254.0.0/16').to_range.begin.to_s == "169.254.0.0" \
    and ::IPAddr.new('169.254.0.0/16').to_range.end.to_s == "169.254.255.255"
    assert ipaddr_has_mask?(::IPAddr.new('169.254.0.0/16'))

    ips_no_mask = ['169.254.0.0/32', '127.0.0.3']
    ips_no_mask.each do |ip_str|
      ip_ = ::IPAddr.new(ip_str)
      assert ip_.instance_variable_get(:@mask_addr).to_s(16) == "ffffffff"
      assert ip_.to_range.begin.to_s == ip_.to_range.end.to_s
      assert !ipaddr_has_mask?(ip_)
    end
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

  # used in self.unsafe_ip_address?(ip_address)
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L148
  # if unsafe_ip_address evaluates to true, the corresponding ip_address will be removed from the set

  # in ruby 3.2, include? is defined as
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

    testing_proc = -> (prefix, num) {
      ::IPAddr.new(prefix + num.to_s)
    }

    (0..255).map { |num| testing_proc.call("127.0.0.", num)}.each do |ip|
      [::IPAddr.new('127.0.0.0/24'), ::IPAddr.new('127.0.3.0/16')].each do |ip_|
        assert ip_.include?(ip)
      end

      [::IPAddr.new('127.0.2.0/24')].each do |ip_|
        assert !ip_.include?(ip)
      end
    end
    # TODO: test some IPV6 addrs
  end

  # from the DEFAULT_RESOLVER used in ssrf-filter, the initialise method of IPAddr:
  # ::IPAddr.new(ip) is called
  # to create IP from the hostname
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L70C36-L71C1
  def test_initialise_IPAddr
    ["127.0.0.1", "[0:0:0:0:0:ffff:127.0.0.1]", "[::ffff:127.0.0.1]"].each do |ip_str|
      # puts ::IPAddr.new(ip_str)
    end
  end

  # creating a request based on the method is used in fetch_once within ssrf_filter.get
  # the response is processed by the block (:stream)
  # https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L118
  # here just print the response of some urls

  # in unscreen: there are 3 keys in option{}: headers, http_option, stream
  # and here they are directly passed in fetch_once
  # images are tested here
  # get method is tested
  def test_fetch_unscreen_image
    image_extensions = {
      "image/jpeg" => "jpg",
      "image/png" => "png",
      "image/gif" => "gif",
    }

    content_type_passlist = image_extensions.keys

    ["https://static.remove.bg/uploader-examples/person/2.jpg"\
    , "https://static.remove.bg/uploader-examples/person/1.jpg"\
    , "https://static.remove.bg/uploader-examples/person/8.jpg"].each do |request_url|

      uri = URI(request_url)

      # 
      ip_addresses = DEFAULT_RESOLVER.call(uri.hostname).reject {|ip| ip.ipv6?}

      # puts "ip addresses are #{ip_addresses.join(' ')}-------------------"

      fetch_once(uri, ip_addresses.sample.to_s, :get,
      headers: {
        "User-Agent" => "unscreen.com/1.0 video background remover",
        "Accept" => content_type_passlist.join(", "),
      }, http_options: {
        open_timeout: 5,
        read_timeout: 5,
        write_timeout: 5,
        ssl_timeout: 5,
      }, stream: proc do |resp|
        puts resp
      end)
    end
  end


  def test_fetch_removebg
  end

end

# test on the ip address of remove.bg
# https://whatismyipaddress.com/hostname-ip
