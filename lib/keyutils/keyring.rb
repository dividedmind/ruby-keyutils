require "keyutils/key"

module Keyutils
  class Keyring < Key
    # Create or update a key
    # @param [String] description the identifier of the key; "app:id" or "subtype:id" format is recommended
    # @param [#to_s] value the contents to set the key to
    # @return [String] the contents the key was set to
    # @see #set
    def []= description, value
      set description, value
    end

    # Create or update a key
    # @overload set(description, value)
    # @overload set(type, description, value)
    # @param [String] type the type of the key; defaults to "user" for general usage
    # @note It is generally not supported to use key types other than "user"
    #   (unless required ie. to interface with other software) and will probably
    #   raise an {SystemCallError}.
    # @param [String] description the identifier of the key; "app:id" or "subtype:id" format is recommended
    # @param [#to_s] value the contents to set the key to
    # @return [Key] the created or updated key
    # @see #[]=
    def set *args
      args = ["user"] + args if args.length == 2
      fail ArgumentError, "wrong number of arguments (#{args.length} for 2..3)" \
          unless args.length == 3
      type, description, value = args

      value = value.to_s
      Key.new Lib.add_key type, description, value, value.size, id
    end

    # Find or create a child keyring
    # @param [String] description the identifier of the keyring
    # @return [Keyring] the found or created keyring
    def subring description
      Keyring.new Lib.add_key 'keyring', description, nil, 0, id
    end

    # special session-specific keyring
    SESSION = Keyring.new Lib::KEY_SPEC[:SESSION_KEYRING]
  end
end
