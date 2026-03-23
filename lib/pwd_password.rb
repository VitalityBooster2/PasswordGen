require_relative "pwd_password/password"
require_relative "pwd_password/storage"
require_relative "pwd_password/cli"

module PwdPassword
end

# Convenience alias so consumers can call `Password.generate(...)` after `require "pwd_password"`.
Object.const_set(:Password, PwdPassword::Password) unless Object.const_defined?(:Password)

