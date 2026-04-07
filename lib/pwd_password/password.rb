# frozen_string_literal: true

require 'securerandom'

module PwdPassword
  class Password
    LOWERCASE = ('a'..'z').to_a.freeze
    UPPERCASE = ('A'..'Z').to_a.freeze
    DIGITS = ('0'..'9').to_a.freeze

    # Reasonable set of ASCII symbols (avoid whitespace, keep URL-unfriendly chars minimal).
    SYMBOLS = %w[
      ! @ # $ % ^ & * ( ) - _ = + [ ] { } ; : , . ? / ~
    ].freeze

    COMMON_PASSWORDS = %w[
      password
      123
      123456789
      123456
      12345678
      111111
      Aa123456
      qwerty
      admin
      letmein
      welcome
      monkey
      iloveyou
      dragon
      football
      sunshine
      passw0rd
    ].freeze

    # ---- Password generation -------------------------------------------------
    #
    # Password.generate(length:, numbers:, symbols:, uppercase:)
    #
    def self.generate(length:, numbers: false, symbols: false, uppercase: false)
      length = Integer(length)
      raise ArgumentError, 'length must be positive' if length <= 0

      # Lowercase is always enabled .
      selected_classes = []
      selected_classes << :lowercase
      selected_classes << :digits if numbers
      selected_classes << :symbols if symbols
      selected_classes << :uppercase if uppercase

      raise ArgumentError, 'length must be >= number of enabled character sets' if length < selected_classes.size

      alphabet = build_alphabet(selected_classes)

      guaranteed = selected_classes.map { |klass| pick_from_class(klass) }

      remaining = length - guaranteed.size
      pool = alphabet
      filler = Array.new(remaining) { pool[SecureRandom.random_number(pool.length)] }

      (guaranteed + filler).shuffle(random: SecureRandom).join
    end

    # ---- Strength estimation ------------------------------------------------
    #
    # Password.strength(password) => { rating: "weak"|"medium"|"strong", crack_time: "..."}
    #
    def self.strength(password)
      pwd = password.to_s
      return { rating: 'weak', crack_time: 'unknown' } if pwd.empty?

      used_sets = detect_used_sets(pwd)
      variety = used_sets.size
      alphabet_size = effective_alphabet_size(used_sets)

      dictionary_hit = dictionary_like?(pwd)
      likely_patterns = pattern_like?(pwd)

      brute_seconds = estimate_bruteforce_seconds(pwd.length, alphabet_size)

      # Dictionary/pattern attacks effectively reduce search space.
      effective_seconds =
        if dictionary_hit
          brute_seconds.nil? ? nil : (brute_seconds / 1_000_000.0)
        elsif likely_patterns
          brute_seconds.nil? ? nil : (brute_seconds / 10_000.0)
        else
          brute_seconds
        end

      rating =
        if dictionary_hit || pwd.length < 10 || variety < 2
          'weak'
        elsif pwd.length >= 14 && variety >= 3 && !likely_patterns
          'strong'
        else
          'medium'
        end

      {
        rating: rating,
        crack_time: human_time(effective_seconds),
        details: {
          length: pwd.length,
          variety: variety,
          used_sets: used_sets.sort,
          alphabet_size: alphabet_size,
          dictionary_hit: dictionary_hit
        }
      }
    end

    # ---- Internals -----------------------------------------------------------
    def self.build_alphabet(selected_classes)
      selected_classes.flat_map do |klass|
        case klass
        when :lowercase then LOWERCASE
        when :uppercase then UPPERCASE
        when :digits then DIGITS
        when :symbols then SYMBOLS
        else
          []
        end
      end
    end
    private_class_method :build_alphabet

    def self.pick_from_class(klass)
      arr =
        case klass
        when :lowercase then LOWERCASE
        when :uppercase then UPPERCASE
        when :digits then DIGITS
        when :symbols then SYMBOLS
        else
          raise ArgumentError, "unknown class: #{klass}"
        end
      arr[SecureRandom.random_number(arr.length)]
    end
    private_class_method :pick_from_class

    def self.detect_used_sets(pwd)
      sets = []
      sets << :lowercase if pwd.match?(/[a-z]/)
      sets << :uppercase if pwd.match?(/[A-Z]/)
      sets << :digits if pwd.match?(/[0-9]/)
      sets << :symbols if pwd.match?(/[^a-zA-Z0-9]/)
      sets
    end
    private_class_method :detect_used_sets

    def self.effective_alphabet_size(used_sets)
      size = 0
      used_sets.each do |klass|
        case klass
        when :lowercase then size += LOWERCASE.size
        when :uppercase then size += UPPERCASE.size
        when :digits then size += DIGITS.size
        when :symbols then size += SYMBOLS.size
        end
      end
      size = 1 if size <= 0
      size
    end
    private_class_method :effective_alphabet_size

    def self.dictionary_like?(pwd)
      down = pwd.downcase
      return true if COMMON_PASSWORDS.include?(down)
      return true if down.length <= 12 && COMMON_PASSWORDS.any? { |w| down.start_with?(w) || down.end_with?(w) }

      return false if down.length > 16

      COMMON_PASSWORDS.any? do |w|
        # Avoid requiring whole word; this is a basic heuristic.
        down.include?(w[0, [w.length, 4].min])
      end
    end
    private_class_method :dictionary_like?

    def self.pattern_like?(pwd)
      # Common human patterns: letters + digits suffix, years, etc.
      !!(pwd.match?(/\A[a-zA-Z]+\d+\z/) || pwd.match?(/\A[a-zA-Z]+\d{2,}\z/) || pwd.match?(/\A[a-zA-Z]+(19|20)\d{2}\z/))
    end
    private_class_method :pattern_like?

    def self.estimate_bruteforce_seconds(length, alphabet_size, attempts_per_second: 1e10)
      return nil if alphabet_size <= 1 || length <= 0

      # Use log10 to avoid huge integers.
      log10_tries = length * Math.log10(alphabet_size)
      log10_seconds = log10_tries - Math.log10(attempts_per_second)

      10**log10_seconds
    end
    private_class_method :estimate_bruteforce_seconds

    def self.human_time(seconds)
      return 'unknown' if seconds.nil? || !seconds.finite?

      s = seconds.to_f

      units = [
        ['секунд', 1.0],
        ['минут', 60.0],
        ['часов', 3600.0],
        ['дней', 86_400.0],
        ['лет', 31_557_600.0]
      ]

      name = units.first[0]
      factor = units.first[1]
      units.each do |u_name, u_factor|
        break if s < u_factor

        name = u_name
        factor = u_factor
      end

      value = s / factor
      formatted =
        if value >= 100
          value.round
        elsif value >= 10
          value.round(1)
        else
          value.round(2)
        end
      "#{formatted} #{name}"
    end
    private_class_method :human_time
  end
end
