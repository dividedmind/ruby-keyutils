module Keyutils
  class Key
    # @return [Fixnum] the numeric ID of the key
    attr_reader :id

    # Create an object representing a preexisting key with the given numeric ID.
    # @note Use {Keyring#set} to actually create keys.
    # @param [Fixnum] id the numeric key identifier
    # @see Keyring#set
    def initialize id
      @id = id
    end
  end
end
