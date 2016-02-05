require "keyutils/version"
require "keyutils/lib"
require "keyutils/key"
require "keyutils/keyring"
require "keyutils/key_perm"

module Keyutils
  LIBRARY_VERSION = Lib.keyutils_version_string[/[\d.]+/].freeze

  include KeyPerm
end
