using Godot;
using System;
using System.Text;

public class TheCrypt : Node2D
{
    private TextEdit _rsaPublic;
    private TextEdit _rsaPrivate;
    private TextEdit _input;
    private TextEdit _output;
    private Button _encryptButton;

    private Crypto _crypto = new Crypto();
    private CryptoKey _MPKey = new CryptoKey();

    public override void _Ready()
    {
        _rsaPublic = GetNode<TextEdit>("RsaPublicKey");
        _rsaPrivate = GetNode<TextEdit>("RsaPrivateKey");
        _input = GetNode<TextEdit>("Input");
        _output = GetNode<TextEdit>("Output");
        _encryptButton = GetNode<Button>("EncryptButton");

        _MPKey.Load("res://mp_private.pem", false);
        _rsaPublic.Text = _MPKey.SaveToString(true);
        _rsaPrivate.Text = _MPKey.SaveToString(false);

        _encryptButton.Connect("pressed", this, "_OnEncryptButtonPressed");
    }

    private void _OnEncryptButtonPressed()
    {
        var timestamp = OS.GetSystemTimeSecs();
        var secretPayload = new ApiPayloadSecurity().EncryptPayload(_input.Text);

        var message = $"{secretPayload}.{timestamp.ToString()}";

        // Hashing & signing:
        var sha256 = new HashingContext();
        sha256.Start(HashingContext.HashType.Sha256);
        sha256.Update(Encoding.UTF8.GetBytes(message));
        var hash = sha256.Finish();

        var signature = _crypto.Sign(HashingContext.HashType.Sha256, hash, _MPKey);
        var signatureText = Marshalls.RawToBase64(signature);

        var output = new Godot.Collections.Dictionary() {
            ["Payload"] = secretPayload,
            ["Timestamp"] = timestamp,
            ["Signature"] = signatureText
        };

        _output.Text = JSON.Print(output, "\t");
    }
}
