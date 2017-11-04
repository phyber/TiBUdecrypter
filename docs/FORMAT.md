# Titanium Backup File Format

## Information Source

This information was originally taken from a post on Christian Egger's G+ page
[here](https://plus.google.com/101760059763010172705/posts/MQBmYhKDex5).
It is recorded here in case that post ever disappears. It has been reformatted
a little for markdown.

## File Format

```
"TB_ARMOR_V1" '\n'
pass_hmac_key '\n'
pass_hmac_result '\n'
public_key '\n'
enc_privkey_spec '\n'
enc_sesskey_spec '\n'
data
```

## Explanation of format

Each of the 5 "variables" (`pass_hmac_key`, `pass_hmac_result`,
`public_key`, `enc_privkey_spec`, `enc_sesskey_spec`) is stored in
Base64 format without linewraps (of course) and can be decoded with:
`Base64.decode(pass_hmac_key, Base64.NO_WRAP)`

Then the user-supplied passphrase (`String`) can be verified as follows:

```
Mac mac = Mac.getInstance("HmacSHA1");
mac.init(new SecretKeySpec(pass_hmac_key, "HmacSHA1"));
byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8"));
boolean passphraseMatches = Arrays.equals(sigBytes, pass_hmac_result);
```

Then the passphrase is independently hashed with SHA-1. We append `0x00` bytes
to the 160-bit result to constitute the 256-bit AES key which is used to
decrypt `enc_privkey_spec` (with an IV of `0x00` bytes).

Then we build the KeyPair object as follows:

```
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
PrivateKey privateKey2 = keyFactory.generatePrivate(
    new PKCS8EncodedKeySpec(privateKey)
);
PublicKey public_key2 = keyFactory.generatePublic(
    new X509EncodedKeySpec(public_key)
);
KeyPair keyPair = new KeyPair(public_key2, privateKey2);
```

Then we decrypt the session key as follows:

```
Cipher rsaDecrypt = Cipher.getInstance("RSA/NONE/PKCS1Padding");
rsaDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
ByteArrayOutputStream baos = new ByteArrayOutputStream();
CipherOutputStream cos = new CipherOutputStream(baos, rsaDecrypt);
cos.write(enc_sesskey_spec); cos.close();
byte[] sessionKey = baos.toByteArray();
```

And finally, we decrypt the data itself with the session key (which can be
either a 128-bit, 192-bit or 256-bit key) and with a `0x00` IV.

While the "zero" IV is suboptimal from a security standpoint, it allows
files to be encoded faster - because every little bit counts, especially
when we store backups with LZO compression.
