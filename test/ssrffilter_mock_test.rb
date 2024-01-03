require "test_helper"

class TestSsrfFilter < Minitest::Test

  # From https://github.com/remove-bg/ssrf_filter/blob/3136dbc8d01fba258eebedba614902964e13d455/lib/ssrf_filter/ssrf_filter.rb#L129C43-L129C43
  # the defined singleton method uses one random public_address from the list "public_addresses" (Array.sample)

  # when testing, some ipv6 addresses that randomly selected will not work, ipv4 addresses work so far

  # for example 2606:4700:20::681a:244:443
  # Errno::EHOSTUNREACH: Failed to open TCP connection to 2606:4700:20::681a:244:443
  # (No route to host - connect(2) for "2606:4700:20::681a:244" port 443)

  # 2606:4700:20::681a:344:443 doesn't work
  # 2606:4700:20::ac43:4724:443 doesn't work
  def test_get_method_image
    image_extensions = {
      "image/jpeg" => "jpg",
      "image/png" => "png",
      "image/gif" => "gif",
    }

    content_type_passlist = image_extensions.keys

    response_ =  ssrf_get("https://static.remove.bg/uploader-examples/person/5.jpg", content_type_passlist)
    assert response_.is_a?(Net::HTTPOK)
    assert response_.code, 200
  end

  def test_post_method
  end
end
