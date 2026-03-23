require "base64"
require "json"
require "openssl"
require "digest"
require "securerandom"

module PwdPassword
  class Storage
    # Encrypted storage format (JSON file):
    # - xor:
    #   { "cipher": "xor", "salt": "...base64...", "ciphertext": "...base64..." }
    # - aes_gcm:
    #   { "cipher": "aes_gcm", "salt": "...", "iv": "...", "tag": "...", "ciphertext": "..." }
    #
    def self.append_password(file_path:, secret:, cipher: "aes_gcm", record:)
      path = file_path.to_s
      raise ArgumentError, "file_path is required" if path.empty?
      raise ArgumentError, "secret is required" if secret.to_s.empty?

      items = load_items(path: path, secret: secret, cipher: cipher)
      items << record
      write_items(path: path, secret: secret, cipher: cipher, items: items)
    end

    def self.load_items(path:, secret:, cipher:)
      return [] unless File.exist?(path)

      payload = JSON.parse(File.read(path))
      stored_cipher = payload["cipher"]
      raise ArgumentError, "Wrong cipher for existing file (expected #{cipher}, got #{stored_cipher})" if stored_cipher && stored_cipher != cipher

      raw = decrypt_blob(
        cipher: stored_cipher || cipher,
        secret: secret,
        payload: payload
      )

      JSON.parse(raw)
    rescue JSON::ParserError
      raise ArgumentError, "Encrypted file format is invalid"
    end

    def self.write_items(path:, secret:, cipher:, items:)
      json = JSON.generate(items)
      payload = encrypt_blob(cipher: cipher, secret: secret, plaintext_json: json)
      File.write(path, JSON.generate(payload))
    end

    def self.encrypt_blob(cipher:, secret:, plaintext_json:)
      cipher = cipher.to_s
      case cipher
      when "xor"
        encrypt_xor(secret: secret, plaintext_json: plaintext_json)
      when "aes_gcm"
        encrypt_aes_gcm(secret: secret, plaintext_json: plaintext_json)
      else
        raise ArgumentError, "Unknown cipher: #{cipher}"
      end
    end
    private_class_method :encrypt_blob

    def self.decrypt_blob(cipher:, secret:, payload:)
      cipher = cipher.to_s
      case cipher
      when "xor"
        decrypt_xor(secret: secret, payload: payload)
      when "aes_gcm"
        decrypt_aes_gcm(secret: secret, payload: payload)
      else
        raise ArgumentError, "Unknown cipher: #{cipher}"
      end
    end
    private_class_method :decrypt_blob

    # Not cryptographically strong (educational), but better than plain text.
    def self.encrypt_xor(secret:, plaintext_json:)
      salt = SecureRandom.random_bytes(16)
      key = Digest::SHA256.digest(secret.to_s + salt.unpack1("H*"))
      bytes = plaintext_json.b

      ciphertext = bytes.bytes.each_with_index.map do |b, i|
        b ^ key.getbyte(i % key.bytesize)
      end.pack("C*")

      {
        "cipher" => "xor",
        "salt" => Base64.strict_encode64(salt),
        "ciphertext" => Base64.strict_encode64(ciphertext)
      }
    end
    private_class_method :encrypt_xor

    def self.decrypt_xor(secret:, payload:)
      salt = Base64.decode64(payload.fetch("salt"))
      key = Digest::SHA256.digest(secret.to_s + salt.unpack1("H*"))
      ciphertext = Base64.decode64(payload.fetch("ciphertext"))

      plaintext = ciphertext.bytes.each_with_index.map do |b, i|
        b ^ key.getbyte(i % key.bytesize)
      end.pack("C*")

      plaintext
    end
    private_class_method :decrypt_xor

    def self.derive_key_aes_gcm(secret, salt)
      # PBKDF2: slow enough to deter trivial guessing, still fast for CLI usage.
      # Using OpenSSL::PKCS5.
      OpenSSL::PKCS5.pbkdf2_hmac(
        secret.to_s,
        salt,
        200_000,
        32,
        "sha256"
      )
    end
    private_class_method :derive_key_aes_gcm

    def self.encrypt_aes_gcm(secret:, plaintext_json:)
      salt = SecureRandom.random_bytes(16)
      key = derive_key_aes_gcm(secret, salt)
      iv = SecureRandom.random_bytes(12) # 96-bit nonce for GCM

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      ciphertext = cipher.update(plaintext_json) + cipher.final
      tag = cipher.auth_tag

      {
        "cipher" => "aes_gcm",
        "salt" => Base64.strict_encode64(salt),
        "iv" => Base64.strict_encode64(iv),
        "tag" => Base64.strict_encode64(tag),
        "ciphertext" => Base64.strict_encode64(ciphertext)
      }
    end
    private_class_method :encrypt_aes_gcm

    def self.decrypt_aes_gcm(secret:, payload:)
      salt = Base64.decode64(payload.fetch("salt"))
      iv = Base64.decode64(payload.fetch("iv"))
      tag = Base64.decode64(payload.fetch("tag"))
      ciphertext = Base64.decode64(payload.fetch("ciphertext"))

      key = derive_key_aes_gcm(secret, salt)

      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag

      cipher.update(ciphertext) + cipher.final
    rescue OpenSSL::Cipher::CipherError
      raise ArgumentError, "Wrong secret (decryption failed)"
    end
    private_class_method :decrypt_aes_gcm
  end
end

