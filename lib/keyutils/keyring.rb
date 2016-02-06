require 'keyutils/key'
require 'keyutils/key_types'

module Keyutils
  class Keyring < Key
    include Enumerable

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
    # @see #each
    def read
      super.unpack('L*').map do |serial|
        # try to map to the correct class
        key = Key.send :new, serial, nil, nil
        Key.send(:new_dispatch, serial, key.type, key.description) rescue key
      end
    end
    alias to_a read
    undef to_s rescue nil

    # Iterate over linked keys
    #
    # @return [Enumerator, Keyring] self if block given, else an Enumerator
    # @yieldparam key [Key] member of the keyring
    # @see #read
    def each &b
      read.each &b
    end

    # Iterate over keys recursively
    #
    # Performs a depth-first recursive scan of the keyring tree and yields for
    # every link found in the accessible keyrings in that tree.
    #
    # Errors are ignored. Inaccessible keyrings are not scanned, but links to
    # them are still yielded. If key attributes (and hence ype) cannot be
    # retrieved, a generic {Key} object is yielded and an error that prevented
    # it is indicated.
    #
    # This method yields for each link found in all the keyrings in the tree
    # and so may be called multiple times for a particular key if that key has
    # multiple links to it.
    #
    # @yieldparam key [Key] the key to which the link points
    # @yieldparam parent [Keyring, nil] the keyring containing the link or nil
    #   for the initial key.
    # @yieldparam attributes [Hash] key attributes, as returned by
    #   {Key#describe}
    # @yieldparam error [SystemCallError, nil] error that prevented retrieving
    #   key attributes
    #
    # @return [Enumerator, Keyring] self if block given, else an Enumerator
    def each_recursive
      return enum_for __method__ unless block_given?

      Lib.recursive_key_scan serial, ->(parent, key, desc, desc_len, _) do
        parent = parent == 0 ? nil : Keyring.send(:new, parent, nil)
        if desc_len > 0
          attributes = Key.send :parse_describe, desc.read_string(desc_len)
          key = Key.send :new_dispatch, key, attributes[:type], attributes[:desc]
          error = nil
        else
          attributes = nil
          key = Key.send :new, key, nil, nil
          error = SystemCallError.new FFI.errno
        end
        yield key, parent, attributes, error
        0
      end, nil
      self
    end

    # @return [Fixnum] number of keys linked to this keyring
    def length
      read.length
    end

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

      # Get the persistent keyring for a user.
      #
      # @note Not every system supports persistent keyrings.
      #
      # Unlike the session and user keyrings, this keyring will persist once
      # all login sessions have been deleted and can thus be used to carry
      # authentication tokens for processes that run without user interaction,
      # such as programs started by cron.
      #
      # The persistent keyring will be created by the kernel if it does not
      # yet exist. Each time this function is called, the persistent keyring
      # will have its expiration timeout reset to the value in
      # +/proc/sys/kernel/keys/persistent_keyring_expiry+ (by default three
      # days). Should the timeout be reached, the persistent keyring will be
      # removed and everything it pins can then be garbage collected.
      #
      # If UID is nil then the calling process's real user ID will be used. If
      # UID is not nil then {Errno::EPERM} will be raised if the user ID
      # requested does not match either the caller's real or effective user
      # IDs or if the calling process does not have _SetUid_ capability.
      #
      # If successful, a link to the persistent keyring will be added into
      # +destination+.
      #
      # @param uid [Fixnum, nil] UID of the user for which the persistent
      #   keyring is requested
      # @param destination [Keyring, nil] keyring to add the persistent keyring
      #   to
      # @return [Keyring] the persistent keyring
      # @raise [Errno::EPERM] not permitted to access the persistent keyring
      #   for the requested UID.
      # @raise [Errno::ENOMEM] insufficient memory to create the persistent
      #   keyring or to extend +destination+.
      # @raise [Errno::ENOKEY] +destination+ does not exist.
      # @raise [Errno::EKEYEXPIRED] +destination+ has expired.
      # @raise [Errno::EKEYREVOKED] +destination+ has been revoked.
      # @raise [Errno::EDQUOT] the user does not have sufficient quota to
      #   extend +destination+.
      # @raise [Errno::EACCES] +destination+ exists, but does not grant write
      #   permission to the calling process.
      # @raise [Errno::EOPNOTSUPP] persistent keyrings are not supported by this
      #   system
      def persistent uid = nil, destination = nil
        Keyring.send \
            :new,
            Lib.keyctl_get_persistent(uid || -1, destination.to_i),
            nil,
            nil
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

    # Set the parent process's session keyring.
    #
    # Changes the session keyring to which the calling process's parent
    # subscribes to be the that of the calling process.
    #
    # The keyring must have link permission available to the calling process,
    # the parent process must have the same UIDs/GIDs as the calling process,
    # and the LSM must not reject the replacement. Furthermore, this may not
    # be used to affect init or a kernel thread.
    #
    # Note that the replacement will not take immediate effect upon the parent
    # process, but will rather be deferred to the next time it returns to
    # userspace from kernel space.
    #
    # @return [Keyring] self
    # @raise [Errno::ENOMEM] insufficient memory to create a key.
    # @raise [Errno::EPERM] the credentials of the parent don't match those of
    #   the caller.
    # @raise [Errno::EACCES] the named keyring exists, but is not linkable by
    #   the calling process.
    def to_parent
      Lib.keyctl_session_to_parent
      self
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
