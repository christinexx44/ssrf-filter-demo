require 'ssrf_filter'

def ssrf_get (url)
  image_extensions = {
    "image/jpeg" => "jpg",
    "image/png" => "png",
    "image/gif" => "gif",
  }

  content_type_passlist = image_extensions.keys

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


    # stream: proc do |response|
    #   status = response.code.to_i
    #   raise DownloadFailed, "Failed to download file (code #{status})" unless status >= 200 && status <= 299

    #   file_size_known = response["content-length"].present?
    #   file_size = response["content-length"].to_i if file_size_known
    #   raise DownloadFailed, "File too large (#{file_size} bytes exceeds limit of #{max_size} bytes)" if file_size_known && file_size > max_size

    #   content_type = response["content-type"]
    #   raise DownloadFailed, "Invalid file type (#{content_type})" unless content_type_passlist.include?(content_type)

    #   bytes_downloaded = 0

    #   File.open target_path, "wb" do |io|
    #     response.read_body do |chunk|
    #       io.write chunk
    #       bytes_downloaded += chunk.size
    #     end
    #     raise DownloadFailed, "File too large (#{file_size} bytes exceeds limit of #{max_size} bytes)" if bytes_downloaded > max_size
    #   end
    # end

end

def ssrf_post
end
