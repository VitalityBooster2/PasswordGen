require 'simplecov'
SimpleCov.start

require "minitest/autorun"
require_relative "../lib/pwd_password"

class TestPassword < Minitest::Test
  def test_generate_length
    pwd = PwdPassword::Password.generate(length: 16)
    assert_equal 16, pwd.length
  end

  def test_generate_includes_requested_sets
    pwd = PwdPassword::Password.generate(length: 20, numbers: true, symbols: true, uppercase: true)
    assert_match(/[a-z]/, pwd)
    assert_match(/[A-Z]/, pwd)
    assert_match(/[0-9]/, pwd)
    assert_match(/[^a-zA-Z0-9]/, pwd)
  end

  def test_strength_dictionary_is_weak
    result = PwdPassword::Password.strength("password")
    assert_equal "weak", result[:rating]
    assert result[:crack_time].to_s.length > 0
  end

  def test_strength_strong_for_varied_long_password
    pwd = PwdPassword::Password.generate(length: 16, numbers: true, symbols: true, uppercase: true)
    result = PwdPassword::Password.strength(pwd)
    assert_includes ["medium", "strong"], result[:rating]
    assert result[:details][:variety] >= 3
  end
end

