require 'spec_helper'

describe Keyutils::Keyring do
  subject(:keyring) { Keyutils::Keyring::SESSION }

  describe '#[]=' do
    it 'sets a key if not present' do
      keyring['test'] = 'bar'
      expect(`keyctl pipe $(keyctl search @s user test)`).to eq 'bar'
    end

    it 'updates a key if present' do
      keyring['test'] = 'baz'
      keyring['test'] = 'xyzzy'
      expect(`keyctl pipe $(keyctl search @s user test)`).to eq 'xyzzy'
    end
  end

  describe '#set' do
    it 'allows specifying arbitrary key type' do
      expect(Keyutils::Lib).to receive(:add_key).
        with('fake', 'keytype', 'content', 7, keyring.id).
        and_return 31337
      expect(keyring.set('fake', 'keytype', 'content').id).to eq 31337
    end

    it 'defaults to "user" type' do
      keyring.set 'app:id', 'content'
      expect(`keyctl pipe $(keyctl search @s user app:id)`).to eq 'content'
    end

    it 'returns a Key instance' do
      key = keyring.set 'app:id', 'content'
      expect(key).to be_a Keyutils::Key
      expect(`keyctl pipe #{key.id}`).to eq 'content'
    end
  end

  describe '#subring' do
    it 'creates a subring' do
      ring = keyring.subring 'test'
      expect(`keyctl search @s keyring test`.to_i).to eq ring.id
    end

    xit 'looks up a subring if it exists' do
      ring = keyring.subring 'test'
      expect(keyring.subring('test').id).to eq ring.id
    end
  end
end
