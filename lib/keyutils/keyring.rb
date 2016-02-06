require 'keyutils/key'
require 'keyutils/key_types'

module Keyutils
  class Keyring < Key
    # Clear the contents of the keyring.
    #
    # The caller must have write permission on a keyring to be able clear it.
    # @return [Keyring] self
    # @raise [Errno::ENOKEY] the keyring is invalid
    # @raise [Errno::EKEYEXPIRED] the keyring has expired
    # @raise [Errno::EKEYREVOKED] the keyring had been revoked
    # @raise [Errno::EACCES] the keyring is not writable by the calling process
    def clear
      Lib.keyctl_clear id
      self
    end

    # Link a key to the keyring.
    #
    # Creates a link from this keyring to +key+, displacing any link to another
    # key of the same type and description in this keyring if one exists.
    #
    # The caller must have write permission on a keyring to be able to create
    # links in it.
    #
    # The caller must have link permission on a key to be able to create a
    # link to it.
    #
    # @param key [Key] the key to link to this keyring
    # @return [Keyring] self
    # @raise [Errno::ENOKEY] the key or the keyring specified are invalid
    # @raise [Errno::EKEYEXPIRED] the key or the keyring specified have expired
    # @raise [Errno::EKEYREVOKED] the key or the keyring specified have been
    #   revoked
    # @raise [Errno::EACCES] the keyring exists, but is not writable by the
    #   calling process
    # @raise [Errno::ENOMEM] insufficient memory to expand the keyring
    # @raise [Errno::EDQUOT] expanding the keyring would exceed the keyring
    #   owner's quota
    # @raise [Errno::EACCES] the key exists, but is not linkable by the
    #   calling process
    # @see #unlink
    def link key
      Lib.keyctl_link key.id, id
      self
    end

    alias << link

    # Unlink a key from the keyring.
    #
    # Removes a link from this keyring to +key+ if it exists.
    #
    # The caller must have write permission on a keyring to be able to remove
    # links in it.
    # @param key [Key] the key to unlink from this keyring
    # @return [Keyring] self
    # @raise [Errno::ENOKEY] the key or the keyring specified are invalid
    # @raise [Errno::EKEYEXPIRED] the key or the keyring specified have expired
    # @raise [Errno::EKEYREVOKED] the key or the keyring specified have been
    #   revoked
    # @raise [Errno::EACCES] the keyring exists, but is not writable by the
    #   calling process
    # @see #link
    def unlink key
      Lib.keyctl_unlink key.id, id
      self
    rescue Errno::ENOENT
      # there was no link
      self
    end

    # Search the keyring for a key
    #
    # Recursively searches the keyring for a key of the specified +type+ and
    # +description+.
    #
    # If found, the key will be attached to the +destination+ keyring (if
    # given), and returned.
    #
    # The source keyring must grant search permission to the caller, and for a
    # key to be found, it must also grant search permission to the caller.
    # Child keyrings will be only be recursively searched if they grant search
    # permission to the caller as well.
    #
    # If the +destination+ keyring is given, then the link may only be formed
    # if the found key grants the caller link permission and the destination
    # keyring grants the caller write permission.
    #
    # If the search is successful, and if the destination keyring already
    # contains a link to a key that matches the specified type and description,
    # then that link will be replaced by a link to the found key.
    #
    # @param type [Symbol] the type of the key to find
    # @param description [String] the description of the key to find
    # @param destination [Keyring, nil] the keyring to attach the key if found
    # @return [Key, nil] the key, if found
    # @raise [Errno::EKEYEXPIRED] one of the keyrings has expired, or the only
    #   key found was expired
    # @raise [Errno::EKEYREVOKED] one of the keyrings has been revoked, or the
    #   only key found was revoked
    # @raise [Errno::ENOMEM] insufficient memory to expand the destination
    #   keyring
    # @raise [Errno::EDQUOT] the key quota for this user would be exceeded by
    #   creating a link to the found key in the destination keyring
    # @raise [Errno::EACCES] the source keyring didn't grant search permission,
    #   the destination keyring didn't grant write permission or the found key
    #   didn't grant link permission to the caller
    # @see Key.request
    def search type, description, destination = nil
      serial = Lib.keyctl_search id, type.to_s, description, destination.to_i
      Key.send :new_dispatch, serial, type.intern, description
    rescue Errno::ENOKEY
      nil
    end

    # Read the keyring.
    #
    # Reads the list of keys in this keyring.
    #
    # The caller must have read permission on a key to be able to read it.
    #
    # @return [<Key>] the keyring members
    # @raise [Errno::ENOKEY] the keyring is invalid
    # @raise [Errno::EKEYEXPIRED] the keyring has expired
    # @raise [Errno::EKEYREVOKED] the keyring had been revoked
    # @raise [Errno::EACCES] the keyring is not readable by the calling process
    # @see #keys
    def read
      super.unpack('L*').map do |serial|
        # try to map to the correct class
        key = Key.send :new, serial, nil, nil
        Key.send(:new_dispatch, serial, key.type, key.description) rescue key
      end
    end
    alias to_a read
    undef to_s

    class << self
      # Set the implicit destination keyring
      #
      # Sets the default destination for implicit key requests for the current
      # thread.
      #
      # After this operation has been issued, keys acquired by implicit key
      # requests, such as might be performed by open() on an AFS or NFS
      # filesystem, will be linked by default to the specified keyring by this
      # function.
      #
      # Only one of the special keyrings can be set as default:
      # - {Thread}
      # - {Process}
      # - {Session}
      # - {User}
      # - {UserSession}
      # - {Group}
      #
      # If +keyring+ is nil, the default behaviour is selected, which is to
      # use the thread-specific keyring if there is one, otherwise the
      # process-specific keyring if there is one, otherwise the session
      # keyring if there is one, otherwise the UID-specific session keyring.
      #
      # @param keyring [Keyring, nil] the new default keyring
      # @return [Keyring, nil] +keyring+
      # @see .default
      def default= keyring = nil
        id = keyring.to_i
        raise ArgumentError, 'only special keyrings can be default' \
            if id > 0
        Lib.keyctl_set_reqkey_keyring -id
      end

      # Get the implicit destination keyring
      #
      # Gets the default destination for implicit key requests for the current
      # thread.
      #
      # Keys acquired by implicit key requests, such as might be performed
      # by open() on an AFS or NFS filesystem, will be linked by default to
      # that keyring.
      #
      # Only one of the special keyrings can be returned:
      # - {Thread}
      # - {Process}
      # - {Session}
      # - {User}
      # - {UserSession}
      # - {Group}
      #
      # If nil is returned, the default behaviour is selected, which is to
      # use the thread-specific keyring if there is one, otherwise the
      # process-specific keyring if there is one, otherwise the session
      # keyring if there is one, otherwise the UID-specific session keyring.
      #
      # @return [Keyring, nil] the default keyring
      # @see .default=
      def default
        [nil, Thread, Process, Session, User, UserSession, Group]\
            [Lib.keyctl_set_reqkey_keyring -1]
      end
    end
  end

  # This module contains the additional methods included in {Keyutils::Keyring::Session}.
  module SessionKeyring
    # Join a different session keyring
    #
    # Change the session keyring to which a process is subscribed.
    #
    # If +name+ is nil then a new anonymous keyring will be created, and the
    # process will be subscribed to that.
    #
    # If +name+ is provided, then if a keyring of that name is available,
    # the process will attempt to subscribe to that keyring, raising an
    # error if that is not permitted; otherwise a new keyring of that name
    # is created and attached as the session keyring.
    #
    # To attach to an extant named keyring, the keyring must have search
    # permission available to the calling process.
    # @param name [String, nil] name of the keyring to join
    # @return [Keyring] the keyring found or created
    # @raise [Errno::ENOMEM] insufficient memory to create a key
    # @raise [Errno::EDQUOT] the key quota for this user would be exceeded
    #   by creating this key or linking it to the keyring
    # @raise [Errno::EACCES] the named keyring exists, but is not searchable
    #   by the calling process
    def join name = nil
      Keyring.send :new, Lib.keyctl_join_session_keyring(name), name
    end
  end

  KeyTypes[:keyring] = Keyring

  class Keyring
    # thread-specific keyring
    Thread = Keyring.new Lib::KEY_SPEC[:THREAD_KEYRING], nil

    # process-specific keyring
    Process = Keyring.new Lib::KEY_SPEC[:PROCESS_KEYRING], nil

    # session-specific keyring
    # @see Keyutils::SessionKeyring
    Session = Keyring.new(Lib::KEY_SPEC[:SESSION_KEYRING], nil).
        extend SessionKeyring

    # UID-specific keyring
    User = Keyring.new Lib::KEY_SPEC[:USER_KEYRING], nil

    # UID-session keyring
    UserSession = Keyring.new Lib::KEY_SPEC[:USER_SESSION_KEYRING], nil

    # GID-specific keyring
    Group = Keyring.new Lib::KEY_SPEC[:GROUP_KEYRING], nil
  end
end
