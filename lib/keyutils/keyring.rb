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
