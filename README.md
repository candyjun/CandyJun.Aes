# CandyJun.Aes
A .Core AES extensions.
- 1.Extensions of RSA
- 2.Compatible with Java
- 3.BC model provide more than .net CLI

Thanks for bcgit's [bc-csharp](https://github.com/bcgit/bc-csharp "bc-csharp")

[![Latest version](https://img.shields.io/nuget/v/CandyJun.Aes.svg?style=flat-square)](https://www.nuget.org/packages/CandyJun.Aes/)
# Install

````shell
Install-Package CandyJun.Aes
````

# Demo

### Init Aes
```csharp
var aes = System.Security.Cryptography.Aes.Create();
aes.Mode = CipherMode.ECB;
aes.Padding = PaddingMode.PKCS7;
aes.BlockSize = 128;
//Generate key equal java SecureRandom (double SHA1)
aes.GenerateKey(8);
aes.GenerateIV(8);
```
### Encrypt with csharp system library and BC library
```csharp
var source = "test";
//Encrypt with csharp system library
var encCsharp = aes.Encrypt(source);

//Encrypt with BC library,params as string
var encBC = aes.EncryptBC(source, "AES/ECB/PKCS7");
```
### Decrypt with csharp system library and BC library
```csharp
//Decrypt with csharp system library
var strCsharp = aes.Decrypt(encCsharp, mode: CipherMode.ECB);

//Decrypt with BC library,params as enum
var strBC = aes.DecryptBC(encCsharp, CipherModeBC.ECB, CipherPaddingBC.PKCS7);
```

## Reference component

 [bc-csharp](https://github.com/bcgit/bc-csharp "bc-csharp") - bcgit

## Change Log

### v1.0.0

#### Features
- Add project