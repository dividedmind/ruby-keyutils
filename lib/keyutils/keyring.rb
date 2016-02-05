require 'keyutils/key'
require 'keyutils/key_types'

module Keyutils
  class Keyring < Key
    # Clears the contents of the keyring.
    #
    # The caller must have write permission on a keyring to be able clear it.
    # @return [Keyring] self
    # @raise [Errno::ENOKEY] the keyring is invalid
    # @raise [Errno::EKEYEXPIRED] the keyring has expired
    # @raise [Errno::EKEYREVOKED] the keyring had been revoked
    # @raise [Errno::EACCES] the keyring is not writable by the calling process
    def clear
      Lib.keyctl_clear serial
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
