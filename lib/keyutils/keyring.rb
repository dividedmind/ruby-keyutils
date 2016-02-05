require 'keyutils/key'
require 'keyutils/key_types'

module Keyutils
  class Keyring < Key
  end

  KeyTypes[:keyring] = Keyring

  class Keyring
    # thread-specific keyring
    Thread = Keyring.new Lib::KEY_SPEC[:THREAD_KEYRING], nil

    # process-specific keyring
    Process = Keyring.new Lib::KEY_SPEC[:PROCESS_KEYRING], nil

    # session-specific keyring
    Session = Keyring.new Lib::KEY_SPEC[:SESSION_KEYRING], nil

    # UID-specific keyring
    User = Keyring.new Lib::KEY_SPEC[:USER_KEYRING], nil

    # UID-session keyring
    UserSession = Keyring.new Lib::KEY_SPEC[:USER_SESSION_KEYRING], nil

    # GID-specific keyring
    Group = Keyring.new Lib::KEY_SPEC[:GROUP_KEYRING], nil
  end
end
