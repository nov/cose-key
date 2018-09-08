require 'openssl'

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

    attr_accessor :kty, :kid, :alg, :ops, :base_iv

    def initialize(attr = {})
      self.kty = attr[KTY]
      self.kid = attr[KID]
      self.alg = attr[ALG]
      self.ops = attr[OPS]
      self.base_iv = attr[BASE_IV]
    end

    class << self
      def decode(cbor)
        new CBOR.decode(cbor)
      end

      def new(attrs = {})
        klass = case attr[KTY]
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
        klass.new attr
      end
    end
  end
end

require 'cose/key/ec2'
require 'cose/key/rsa'