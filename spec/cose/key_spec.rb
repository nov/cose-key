RSpec.describe COSE::Key do
  let(:ec2_cbor) do
    "\xA5\x01\x02\x03& \x01!X \x06\x0F\xBD\x82\xE5U\xC4\xDEl\f\x8F7?_O\xFB\xC1H\b8\x0E\xA4\xB7b\xA8\f\x89\xF5\xFBS\xC7u\"X \n\x19\x98\x15\xF2\x10\x99#\xBE[\xB6\xE7PCo\xC5h:\xD2$z\xD0\x03\xD5[\xD8su\x94$\x9A\xD9"
  end
  let(:ec2_pem) do
    <<~PEM
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBg+9guVVxN5sDI83P19P+8FICDgO
    pLdiqAyJ9ftTx3UKGZgV8hCZI75btudQQ2/FaDrSJHrQA9Vb2HN1lCSa2Q==
    -----END PUBLIC KEY-----
    PEM
  end
  let(:ec2_key) { OpenSSL::PKey::EC.new ec2_pem }
  let(:decoded) { COSE::Key.decode cbor }

  context 'for EC keys' do
    let(:cbor) { ec2_cbor }

    describe '.decode' do
      subject { decoded }
      it { should be_instance_of COSE::Key::EC2 }
    end

    describe '#curve_name' do
      subject { decoded.curve_name }
      it { should == 'prime256v1' }
    end

    describe '#digest' do
      subject { decoded.digest }
      it { should be_instance_of OpenSSL::Digest::SHA256 }
    end

    describe '#to_key' do
      subject { decoded.to_key }
      it { should be_instance_of OpenSSL::PKey::EC }
    end

    # describe '#to_s' do
    #   subject { decoded.to_s }
    #   it { should == ec2_cbor }
    # end

    describe '#to_pem' do
      subject { decoded.to_pem }
      it { should == ec2_pem }
    end

    describe '#to_text' do
      subject { decoded.to_text }
      it { should == ec2_key.to_text }
    end
  end

  context 'for RSA keys' do
    it :TODO
  end
end
