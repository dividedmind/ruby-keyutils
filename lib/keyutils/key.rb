module Keyutils
  class Key
    class << self
      # Add a key to the kernel's key management facility.
      #
      # Asks the kernel to create or update a key of the given +type+ and
      # +description+, instantiate it with the +payload+, and to attach it to
      # the nominated +keyring+.
      #
      # The key type may reject the data if it's in the wrong format or in
      # some other way invalid.
      #
      # Keys of the user-defined key type ("user") may contain a blob of
      # arbitrary data, and the description may be any valid string, though it
      # is preferred that the description be prefixed with a string
      # representing the service to which the key is of interest and a colon
      # (for instance "afs:mykey").
      #
      # If the destination keyring already contains a key that matches the
      # specified type and description then, if the key type supports it, that
      # key will be updated rather than a new key being created; if not, a new
      # key will be created and it will displace the link to the extant key
      # from the keyring.
      #
      # @param type [String] key type
      # @param description [String] key description
      # @param payload [#to_s, nil] payload
      # @param keyring [Keyring] destination keyring; a valid keyring to which
      #   the caller has write permission
      # @return [Key] the key created or updated
      # @raise [Errno::ENOKEY] the keyring doesn't exist
      # @raise [Errno::EKEYEXPIRED] the keyring has expired
      # @raise [Errno::EKEYREVOKED] the keyring has been revoked
      # @raise [Errno::EINVAL] the payload data was invalid
      # @raise [Errno::ENODEV] the key type was invalid
      # @raise [Errno::ENOMEM] insufficient memory to create a key
      # @raise [Errno::EDQUOT] the key quota for this user would be exceeded by
      #   creating this key or linking it to the keyring
      # @raise [Errno::EACCES] the keyring wasn't available for modification by
      #   the user
      def add type, description, payload, keyring
        serial = Lib.add_key \
            type,
            description,
            payload && payload.to_s,
            payload && payload.length || 0,
            keyring.to_i
        new serial, type, description
      end

      # Request a key from the kernel's key management facility.
      #
      # Asks the kernel to find a key of the given +type+ that matches the
      # specified +description+ and, if successful, to attach it to the
      # nominated +keyring+.
      #
      # {.request} first recursively searches all the keyrings attached to the
      # calling process in the order thread-specific keyring, process-specific
      # keyring and then session keyring for a matching key.
      #
      # If {.request} is called from a program invoked by request_key(2) on
      # behalf of some other process to generate a key, then the keyrings of
      # that other process will be searched next, using that other process's
      # UID, GID, groups and security context to control access.
      #
      # The keys in each keyring searched are checked for a match before any
      # child keyrings are recursed into. Only keys that are searchable for
      # the caller may be found, and only searchable keyrings may be searched.
      #
      # If the key is not found then, if +callout_info+ is not nil, this
      # function will attempt to look further afield. In such a case, the
      # +callout_info+ is passed to a user-space service such as
      # +/sbin/request-key+ to generate the key.
      #
      # If that is unsuccessful also, then an error will be raised, and a
      # temporary negative key will be installed in the nominated keyring. This
      # will expire after a few seconds, but will cause subsequent calls to
      # {.request} to fail until it does.
      #
      # If a key is created, no matter whether it's a valid key or a negative
      # key, it will displace any other key of the same type and description
      # from the destination keyring.
      # @param type [String] key type
      # @param description [String] key description
      # @param callout_info [String, nil] additional parameters for the
      #   request-key(8) facility
      # @param keyring [Keyring] the destination keyring; a valid keyring to
      #   which the caller has write permission
      # @return [Key, nil] the key, if found
      # @raise [Errno::EACCES] the keyring wasn't available for modification by the user
      # @raise [Errno::EINTR] the request was interrupted by a signal
      # @raise [Errno::EDQUOT] the key quota for this user would be exceeded by creating this key or linking it to the keyring
      # @raise [Errno::EKEYEXPIRED] an expired key was found, but no replacement could be obtained
      # @raise [Errno::EKEYREJECTED] the attempt to generate a new key was rejected
      # @raise [Errno::EKEYREVOKED] a revoked key was found, but no replacement could be obtained
      # @raise [Errno::ENOMEM] insufficient memory to create a key
      def request type, description, callout_info, keyring
        serial = Lib.request_key type, description, callout_info, keyring.to_i
        new serial, type, description
      rescue Errno::ENOKEY
        nil
      end

      private :new
    end

    private
    def initialize id, type, description
      @id = id
      @type = type
      @description = description
    end
  end
end
