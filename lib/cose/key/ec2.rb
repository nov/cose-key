module COSE
  class Key
    class EC2 < Key
      CRV = -1
      X = -2
      Y = -3
      D = -4

      ALGS = {
        ES256: -7,
        ES384: -35,
        ES512: -36
      }
      CRVS = {
        P256: 1,
        P384: 2,
        P521: 3
      }

      attr_accessor :crv, :x, :y, :d

      def initialize(attrs = {})
        super
        self.crv = attrs[CRV]
        self.x = attrs[X]
        self.y = attrs[Y]
        self.d = attrs[D]
      end

      def alg_key
        ALGS.invert[alg] or
        raise UknownAlgorithm, 'Unknown Algorithm'
      end

      def crv_key
        CRVS.invert[crv] or
        raise UknownAlgorithm, 'Unknown Curve'
      end

      def crv_name
        case crv_key
        when :P256
          'prime256v1'
        when :P384
          'secp384r1'
        when :P521
          'secp521r1'
        end
      end

      def digest
        case alg_key
        when :ES256
          OpenSSL::Digest::SHA256
        when :ES384
          OpenSSL::Digest::SHA384
        when :ES512
          OpenSSL::Digest::SHA512
        end.new
      end

      def to_key
        key = OpenSSL::PKey::EC.new crv_name
        key.private_key = OpenSSL::BN.new(d, 2) if d
        key.public_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(crv_name),
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