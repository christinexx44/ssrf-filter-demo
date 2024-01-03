require 'ssrf_filter'

def ssrf_get(url, content_type_passlist)
  SsrfFilter.get(
    url ,
    headers: {
      "User-Agent" => "unscreen.com/1.0 video background remover",
      "Accept" => content_type_passlist.join(", "),
    },
    http_options: {
      open_timeout: 5,
      read_timeout: 5,
      write_timeout: 5,
      ssl_timeout: 5,
  })
end

def ssrf_post(url)
  SsrfFilter.post(url)
end
