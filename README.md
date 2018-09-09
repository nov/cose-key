# COSE::Key

COSE Key (RSA & EC) in Ruby

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cose-key'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cose-key

## Usage

```ruby
require 'cose/key'

cose_key_in_cbor = "\xA5\x01\x02\x03& \x01!X \x06\x0F\xBD\x82\xE5U\xC4\xDEl\f\x8F7?_O\xFB\xC1H\b8\x0E\xA4\xB7b\xA8\f\x89\xF5\xFBS\xC7u\"X \n\x19\x98\x15\xF2\x10\x99#\xBE[\xB6\xE7PCo\xC5h:\xD2$z\xD0\x03\xD5[\xD8su\x94$\x9A\xD9"

cose_key = COSE::Key.decode cose_key_in_cbor
# => COSE::Key::EC2 or COSE::Key::RSA

cose_key.to_key
# => OpenSSL::PKey::EC or OpenSSL::PKey::RSA

cose_key.alg_key
# => :RS256, :ES256 etc.

cose_key.digest
# => OpenSSL::Digest::SHA(1|256|384|512) instance per algorithm.
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `VERSION`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nov/cose-key.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
