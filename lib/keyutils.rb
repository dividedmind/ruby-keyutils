require "keyutils/version"
require "keyutils/lib"
require "keyutils/key"

module Keyutils
  LIBRARY_VERSION = Lib.keyutils_version_string[/[\d.]+/].freeze
end
