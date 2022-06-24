using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;

public class ApiPayloadSecurity
{
    private RsaKeyParameters _apiPublicKey;

    private string _apiPublicKeyText = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2zE9zZVGdQ2MplGLc43Y
Tf1/SofwI5uqOsGMP6uvVTPZgxJEQMoxA9954VPss6OR1vpNj7GTSkZeWZhXt3rZ
ruVVwgoQr0CUA1geMnMEmqeWHTRZa/JwzH/CHoacnzXYIzk96P/Mz7yZwgsYCCFZ
aHyDwT4bxXpvzhMKmdGGpkIRNdRPEuUtAnMioQ5kO+P8BDUmxeledW1xg2TUotyg
8uJ0NbsxSrcRKPlGm/n9yeeMN9Vgh9mBoO0Iflytsi8V28VK9pl+JM4cz/dqbjn+
df/1acu0YalGo4ksnoZ77Olmzf8Y5QfjbGKeFnaGNVFEcHt35R5Cbj68Cv53vfCf
DuYFewH63vyUlt+AejqPGh+5WvrWnEM7O2cAio/ZIGbqioOLxGHHtSQn9EO1E5Xo
oOrOw6DT8hNexF5Ti4p3yzg785INzpheCAnydHyLx5Hh0hLX/4LwXfk0cpoPLZFD
QYrW1ODx86iMS1U9xGd+HhVRYRp4rKB7qj4bZgwPkrQbmT00dJfi9Ar8278/h/fM
+gOJ5G6mt9Klw/A9kByA0mt+XD7s07kX4sSVmetPHVRnVHP8Um4Yza94paQF5p7G
ur55ic2lO6xmsVsz1pL79741SwwLLAfg0TlX7He2Rzz7D3IdbIPmS0BzIaDaVAVb
c718MtMpIdkKSiGzwRKVTjMCAwEAAQ==
-----END PUBLIC KEY-----";

    public ApiPayloadSecurity()
    {
        using (var stringReader = new StringReader(_apiPublicKeyText))
        {
            var pemReader = new PemReader(stringReader);
            _apiPublicKey = (RsaKeyParameters) pemReader.ReadObject();
        }
    }

    public string EncryptPayload(string payload)
    {
        var engine = new Pkcs1Encoding(new RsaEngine());
        engine.Init(forEncryption: true, _apiPublicKey);

        var data = Encoding.UTF8.GetBytes(payload);
        var encryptedData = engine.ProcessBlock(data, 0, data.Length);

        return Convert.ToBase64String(encryptedData);
    }
}