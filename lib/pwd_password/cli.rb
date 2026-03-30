require "json"
require "optparse"
require_relative "password"
require_relative "storage"

module PwdPassword
  class CLI
    def self.run(argv)
      cmd = argv.shift
      case cmd
      when "generate"
        run_generate(argv)
      when "check"
        run_check(argv)
      when "decrypt"
        run_decrypt(argv)
      when nil
        usage(io: $stdout)
      else
        $stderr.puts "Unknown command: #{cmd}"
        usage(io: $stderr)
        exit 1
      end
    end

    def self.usage(io:)
      io.puts <<~TXT
        Usage:
          pwd generate --length 16 --symbols --numbers --uppercase [--store FILE --secret SECRET --cipher aes_gcm|xor]
          pwd check "password"
          pwd decrypt --file FILE --secret SECRET [--cipher aes_gcm|xor]

        Notes:
          In PowerShell, `pwd` is an alias for `Get-Location`.
          If the alias blocks the command, run `pwd.exe ...` instead after installing the gem.
      TXT
    end
    private_class_method :usage

    def self.run_generate(argv)
      options = {
        length: 16,
        numbers: false,
        symbols: false,
        uppercase: false,
        store: nil,
        secret: ENV["PWD_SECRET"],
        cipher: "aes_gcm"
      }

      parser = OptionParser.new do |opts|
        opts.banner = "pwd generate [options]"
        opts.on("--length N", Integer, "Password length (>= 1)") { |v| options[:length] = v }
        opts.on("--numbers", "Include digits") { options[:numbers] = true }
        opts.on("--symbols", "Include symbols") { options[:symbols] = true }
        opts.on("--uppercase", "Include uppercase letters") { options[:uppercase] = true }
        opts.on("--store FILE", "Append generated passwords to encrypted store") { |v| options[:store] = v }
        opts.on("--secret SECRET", "Secret/passphrase for encryption (default: env PWD_SECRET)") { |v| options[:secret] = v }
        opts.on("--cipher aes_gcm|xor", "Cipher for encrypted store (default: aes_gcm)") { |v| options[:cipher] = v }
        opts.on("-h", "--help", "Show help") do
          puts opts
          exit
        end
      end

      parser.parse!(argv)

      password = Password.generate(
        length: options[:length],
        numbers: options[:numbers],
        symbols: options[:symbols],
        uppercase: options[:uppercase]
      )

      puts password

      return unless options[:store]

      if options[:secret].to_s.empty?
        $stderr.puts "Missing --secret (or set env PWD_SECRET) to encrypt store."
        exit 1
      end

      record = {
        "password" => password,
        "created_at" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params" => {
          "length" => options[:length],
          "numbers" => options[:numbers],
          "symbols" => options[:symbols],
          "uppercase" => options[:uppercase]
        }
      }

      Storage.append_password(
        file_path: options[:store],
        secret: options[:secret],
        cipher: options[:cipher],
        record: record
      )

      # Print a small message to stderr to keep stdout clean for scripts.
      $stderr.puts "Saved password to #{options[:store]} (cipher=#{options[:cipher]})."
    end

    def self.run_check(argv)
      if argv.empty?
        $stderr.puts "Missing password argument."
        usage(io: $stderr)
        exit 1
      end

      password = argv.join(" ")
      result = Password.strength(password)

      # Human-readable output + JSON details for scripts.
      puts "rating: #{result[:rating]}"
      puts "crack_time: #{result[:crack_time]}"
      puts "details: #{JSON.generate(result[:details])}"
    end

    def self.run_decrypt(argv)
      options = {
        file: nil,
        secret: ENV["PWD_SECRET"],
        cipher: "aes_gcm"
      }

      parser = OptionParser.new do |opts|
        opts.banner = "pwd decrypt [options]"
        opts.on("--file FILE", "Encrypted storage file (e.g. passwords.enc)") { |v| options[:file] = v }
        opts.on("--secret SECRET", "Secret/passphrase (default: env PWD_SECRET)") { |v| options[:secret] = v }
        opts.on("--cipher aes_gcm|xor", "Cipher (default: aes_gcm)") { |v| options[:cipher] = v }
        opts.on("-h", "--help", "Show help") do
          puts opts
          exit
        end
      end

      parser.parse!(argv)

      if options[:file].to_s.empty?
        $stderr.puts "Missing --file."
        exit 1
      end

      if options[:secret].to_s.empty?
        $stderr.puts "Missing --secret (or set env PWD_SECRET)."
        exit 1
      end

      items = Storage.load_items(path: options[:file], secret: options[:secret], cipher: options[:cipher])
      puts JSON.pretty_generate(items)
    rescue ArgumentError => e
      $stderr.puts e.message
      exit 1
    end
  end
end

