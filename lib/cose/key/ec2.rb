module Cose
  class Key
    class EC2 < Key
      CRV = -1
      X = -2
      Y = -3
      D = -4

      ES256 = -7
      ES384 = -35
      ES512 = -36

      P256 = 1
      P384 = 2
      P521 = 3

      attr_accessor :crv, :x, :y

      def initialize(attrs = {})
        super
        self.crv = attrs[CRV]
        self.x = attrs[X]
        self.y = attrs[Y]
        self.d = attrs[D]
      end

      def curve_name
        case crv
        when P256
          'prime256v1'
        when P384
          'secp384r1'
        when P521
          'secp521r1'
        else
          raise 'Unknown Curve'
        end
      end

      def digest
        case alg
        when ES256
          OpenSSL::Digest::SHA256
        when ES384
          OpenSSL::Digest::SHA384
        when ES512
          OpenSSL::Digest::SHA512
        else
          raise 'Unknown Algorithm'
        end.new
      end

      def to_key
        key = OpenSSL::PKey::EC.new curve_name
        key.private_key = OpenSSL::BN.new(d, 2) if d
        key.public_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve_name),
          OpenSSL::BN.new([
            '04' +
            x.unpack('H*').first +
            y.unpack('H*').first
          ].pack('H*'), 2)
        )
        key
      end
    end
  end
end