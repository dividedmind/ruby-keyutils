require "keyutils/version"
require "keyutils/lib"

module Keyutils
  LIBRARY_VERSION = Lib.keyutils_version_string[/[\d.]+/].freeze
end
