# OIDCAndroidLib

An Android library to connect to [OpenID Connect](http://openid.net/connect/) providers.

This library relies on [google-oauth-java-client](https://code.google.com/p/google-oauth-java-client/) which is part of [Google APIs Client Library for Java](https://github.com/google/google-api-java-client) and is meant to connect to non-Google providers, which those APIs don’t support. Use [Google’s own APIs](https://developers.google.com/accounts/docs/OAuth2Login), when dealing with their providers.

## Features

* Runs on Android API 9 and upwards
* Integration with Android’s AccountManager
* Supports Code, Implicit, Hybrid Flows (Password is also supported as OAuth2 Flow)
* Login and authorisation via a WebView (native form is used for Password Flow)
* Automatic refresh tokens when needed or pops notification when invalid
* Easy openidconnect/oauth2 client and server endpoints configuration
* Token secure storage (relies on [Keystore](http://developer.android.com/training/articles/keystore.html) for Andoid Api 23 upwards, [Spongy Castle](https://rtyley.github.io/spongycastle) otherwise)
* Can be used as OAuth2 client
* ~~Support for multiple accounts~~

**Dev only** : the following features are provided to help developpent and should **NEVER** be use on a production context.

* In app openidconnect/oauth2 client configuration editor
* Allows to disable SSL checks/certificate validation

## Usage

Use one of the following options to set the library dependency with to your project :

**1. Gradle**
```gradle
compile 'com.kalemontes.oidc:openidconnect-android-client:0.2.1'
```

**2. Maven**
```xml
<dependency>
  <groupId>com.kalemontes.oidc</groupId>
  <artifactId>openidconnect-android-client</artifactId>
  <version>0.2.1</version>
  <type>pom</type>
</dependency>
```

**3. Aar file**

* Download the latest .aar file from the [releases section]()
* Use the AndroidStudio .jar/.aar native import under `File -> New Module -> Import .JAR/.AAR`

> Have a look at the [Wiki](https://github.com/kalemontes/OIDCAndroidLib/wiki) for the [detailed procedure]().

**4. Clone repo**

* Clone from `https://github.com/kalemontes/OIDCAndroidLib.git` or `git@github.com:kalemontes/OIDCAndroidLib.git`
* Use the AndroidStudio gradle project import under `File -> New Module -> Import Gradle Project`

> Have a look at the [Wiki](https://github.com/kalemontes/OIDCAndroidLib/wiki) for the [detailed procedure](https://github.com/kalemontes/OIDCAndroidLib/wiki/Setting-up-the-sample-project).

## Configuration

> Have a look at the [Wiki](https://github.com/kalemontes/OIDCAndroidLib/wiki) for the [detailed procedure](https://github.com/kalemontes/OIDCAndroidLib/wiki/Using-the-lib).

## Documentation

For a detailed documentation have a look at the [Wiki](https://github.com/kalemontes/OIDCAndroidLib/wiki) or the [JavaDocs]().

If you are having trouble setting up the library you can also check out the example code project in the [oidclib-sample](https://github.com/kalemontes/OIDCAndroidLib/tree/master/oidclib-sample) directory.

## History

This library was inspired from the [OpenID Connect Sample for Android](https://github.com/learning-layers/android-openid-connect) project developed by [Leo Nikkilä](https://github.com/lnikkila). It renews the will to convert that [project to a library](https://github.com/learning-layers/android-openid-connect/issues/2) following [Leo Nikkilä's](https://github.com/lnikkila) intended goals :

> The goal of the library is to provide:
>
> * Support for all OpenID Connect flows
> * AccountManager integration
> * Sane defaults that can be overridden for custom behaviour

#License 

Licensed under the ISC License (ISC)

Copyright (c) 2015, Camilo Montes

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

