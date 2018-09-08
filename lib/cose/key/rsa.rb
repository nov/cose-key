module Cose
  class Key
    class RSA < Key
      N = -1
      E = -2
      D = -3
      P = -4
      Q = -5
      DP = -6
      DQ = -7
      QI = -8

      PS256 = -37
      PS384 = -38
      PS512 = -39
      RSAES_OAEP_SHA1   = -40
      RSAES_OAEP_SHA256 = -41
      RSAES_OAEP_SHA512 = -42

      attr_accessor :n, :e, :d, :p, :q, :dp, :dq, :qi

      def initialize(attrs = {})
        super
        self.n = attrs[N]
        self.e = attrs[E]
        self.d = attrs[D]
        self.p = attrs[P]
        self.q = attrs[Q]
        self.dp = attrs[DP]
        self.dq = attrs[DQ]
        self.qi = attrs[QI]
      end

      def digest
        case alg
        when RSAES_OAEP_SHA1
          OpenSSL::Digest::SHA1
        when PS256, RSAES_OAEP_SHA256
          OpenSSL::Digest::SHA256
        when PS384
          OpenSSL::Digest::SHA384
        when PS512, RSAES_OAEP_SHA512
          OpenSSL::Digest::SHA512
        else
          raise 'Unknown Algorithm'
        end.new
      end

      def to_key
        key = OpenSSL::PKey::RSA.new
        if key.respond_to? :set_key
          key.set_key n, e, d
          key.set_factors p, q if p && q
          key.set_crt_params dp, dq, qi if dp && dq && qi
        else
          key.e = e
          key.n = n
          key.d = d if d
          key.p = p if p
          key.q = q if q
          key.dmp1 = dp if dp
          key.dmq1 = dq if dq
          key.iqmp = qi if qi
        end
        key
      end
    end
  end
end