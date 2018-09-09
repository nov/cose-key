require 'openssl'
require 'cbor'

module COSE
  class Key
    KTY = 1
    KID = 2
    ALG = 3
    OPS = 4
    BASE_IV = 5

    KTY_OKP = 1
    KTY_EC2 = 2
    KTY_RSA = 3
    KTY_SYMMETRIC = 4

    attr_accessor :kty, :kid, :alg, :ops, :base_iv, :raw

    def initialize(attrs = {})
      self.kty = attrs[KTY]
      self.kid = attrs[KID]
      self.alg = attrs[ALG]
      self.ops = attrs[OPS]
      self.base_iv = attrs[BASE_IV]
    end

    def alg_key
      raise 'Implement me'
    end

    def digest
      raise 'Implement me'
    end

    def to_key
      raise 'Implement me'
    end

    class << self
      def decode(cbor)
        key = detect CBOR.decode(cbor)
        key.raw = cbor
        key
      end

      def detect(attrs = {})
        klass = case attrs[KTY]
        when KTY_OKP
          raise 'Unsupported Key Type: OKP'
        when KTY_EC2
          EC2
        when KTY_RSA
          RSA
        when KTY_SYMMETRIC
          raise 'Unsupported Key Type: Symmetric'
        else
          raise 'Unknown Key Type'
        end
        klass.new attrs
      end
    end
  end
end

require 'cose/key/ec2'
require 'cose/key/rsa'