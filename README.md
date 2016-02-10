# Keyutils

This is a wrapper for keyutils library, providing idiomatic Ruby interface for
Linux kernel keyring.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'keyutils'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install keyutils

## Usage

```ruby
require 'keyutils'
include Keyutils

ring = Key.find 'keyring', 'myring'
puts "My very secret key is #{ring['secret:key']}"

new_session = Keyring::Session.join
ring = new_session.add 'keyring', 'newring', nil
ring['foo'] = 'bar'
puts `keyctl show @s`

# prints:
# Keyring
#  496820604 --alswrv   1000  1001  keyring: _ses
#  145266026 --alswrv   1000  1001   \_ keyring: newring
#  169205931 --alswrv   1000  1001       \_ user: foo
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/dividedmind/keyutils.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

