module Keyutils
  # Key permission constants.
  # @see Key#setperm
  module KeyPerm
    KEY_POS_VIEW = 0x01000000 # possessor can view a key's attributes
    KEY_POS_READ = 0x02000000 # possessor can read key payload / view keyring
    KEY_POS_WRITE = 0x04000000 # possessor can update key payload / add link to keyring
    KEY_POS_SEARCH = 0x08000000 # possessor can find a key in search / search a keyring
    KEY_POS_LINK = 0x10000000 # possessor can create a link to a key/keyring
    KEY_POS_SETATTR = 0x20000000 # possessor can set key attributes
    KEY_POS_ALL = 0x3f000000

    #
    # user permissions...
    #

    KEY_USR_VIEW = 0x00010000
    KEY_USR_READ = 0x00020000
    KEY_USR_WRITE = 0x00040000
    KEY_USR_SEARCH = 0x00080000
    KEY_USR_LINK = 0x00100000
    KEY_USR_SETATTR = 0x00200000
    KEY_USR_ALL = 0x003f0000

    #
    # group permissions...
    #

    KEY_GRP_VIEW = 0x00000100
    KEY_GRP_READ = 0x00000200
    KEY_GRP_WRITE = 0x00000400
    KEY_GRP_SEARCH = 0x00000800
    KEY_GRP_LINK = 0x00001000
    KEY_GRP_SETATTR = 0x00002000
    KEY_GRP_ALL = 0x00003f00

    #
    # third party permissions...
    #

    KEY_OTH_VIEW = 0x00000001
    KEY_OTH_READ = 0x00000002
    KEY_OTH_WRITE = 0x00000004
    KEY_OTH_SEARCH = 0x00000008
    KEY_OTH_LINK = 0x00000010
    KEY_OTH_SETATTR = 0x00000020
    KEY_OTH_ALL = 0x0000003f
  end
end
