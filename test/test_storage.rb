require "minitest/autorun"
require "fileutils"
require_relative "../lib/pwd_password"

class TestStorage < Minitest::Test
  def with_tempfile
    require "tmpdir"
    dir = Dir.mktmpdir
    path = File.join(dir, "store.enc")
    yield path
  ensure
    FileUtils.rm_rf(dir) if dir
  end

  def test_aes_gcm_append_and_load
    secret = "secret-pass"
    record = { "password" => "Abc123!xYz", "created_at" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ") }

    with_tempfile do |path|
      PwdPassword::Storage.append_password(file_path: path, secret: secret, cipher: "aes_gcm", record: record)
      items = PwdPassword::Storage.load_items(path: path, secret: secret, cipher: "aes_gcm")
      assert_equal 1, items.size
      assert_equal record["password"], items.first["password"]
    end
  end

  def test_xor_append_and_load
    secret = "secret-pass"
    record = { "password" => "Abc123!xYz", "created_at" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ") }

    with_tempfile do |path|
      PwdPassword::Storage.append_password(file_path: path, secret: secret, cipher: "xor", record: record)
      items = PwdPassword::Storage.load_items(path: path, secret: secret, cipher: "xor")
      assert_equal 1, items.size
      assert_equal record["password"], items.first["password"]
    end
  end
end

