# FooTOTP

## Introduction
FooTOTP is a command-line TOTP client for Unix-like systems. It generates 2FA
codes from your secret-keys.

## Usage

```
Usage: foototp OPTIONS COMMAND ARG
Commands:
	configure
	add ARG
	remove ARG
	generate ARG
	encrypt
	list
Options:
	-v Verbose mode (when used with 'add' or 'list').
	-c Copy generated code to clipboard (when used with 'add' or 'generate').
```

## Examples

```
$ foototp
foototp: Please first configure FooTOTP by running 'foototp configure'.

$ foototp configure
Configuring FooTOTP . . .
Path to 2FA keychain (will be created if it does not exist): ~/this/does/not/exist.json
"/home/x/this/does/not/exist.json" not found . . . Creating file . . .
"/home/x/this/does/not/exist.json" created . . .
Configured FooTOTP! Run 'foototp encrypt' to encrypt your keychain.

$ foototp encrypt
Note–Leave the password blank to disable encryption.
Enter the password you want to use (no echo):
Confirm password:
Encryption has been enabled on your 2FA keychain.

$ foototp add sourcehut
Unlock the keychain (no echo):
Enter shared-secret: JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
TOTP: 529848
2FA key added.

$ foototp -c generate sourcehut
Unlock the keychain (no echo):
TOTP: 497701 (Copied to clipboard.)

$ foototp list
Unlock the keychain (no echo):
sourcehut

$ foototp -v list
name,secret_key,hash_function,digits,time_step
sourcehut,JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP,SHA1,6,30

$ foototp encrypt
Unlock the keychain (no echo):
Your keychain is already encrypted. Update password? (y/n): y
Note–Leave the password blank to disable encryption.
Enter the password you want to use (no echo):
Confirm password:
Encryption has been enabled on your 2FA keychain.
```

## Installation (by Building from Source)

### Requirements
* Go >= 1.16
* The -c flag has special requirements, depending on the display protocol you
  are using:
    * If you're using X11, you will need either `xsel` or `xclip`.
    * If you're on Wayland, you will need `wl-clipboard`.

### Building
Clone the repository, run `go build`, and place the resultant executable in one
of your $PATH folders (such as `~/.local/bin`):

```
$ git clone https://codeberg.org/ar324/foototp
$ cd foototp
$ go build -o foototp .
$ mv ./foototp ~/.local/bin
```


## Why 2FA?

_Oscar is a malicious actor. Alice is an angel in Wonderland._

2FA's raison d'etre is to serve as an additional loop for Oscar to jump through
if he somehow obtains Alice's password(s) for the online services she uses.
With 2FA, Alice's passwords alone wouldn't be enough for Oscar to log in to her
accounts.  He would need _something else_ to authenticate as Alice. The most
ubiquitous 2FA mechanism today is TOTP, which uses time-based one-time passwords
as that _something else_.

Oscar could have obtained her keys from a data breach, a malicious program on
her computer (such as a key-logger), or some other mechanism such as social
engineering.

## What Is a 2FA Client?

A 2FA client stores your 2FA secret-keys (the _seeds_ from which OTPs are
generated). When you request your client to generate an OTP, it performs some
numerical computations on the _seed_ to give you your code.

2FA clients are largely used on smartphones instead of on computers. I am
assuming this is because people always have their smartphones on them, which
lets them access their accounts at any time. Using a 2FA client on a separate
device also reduces the probability of security threats.

## Why a Desktop 2FA Client? Why FooTOTP?

While I already use [Aegis](https://github.com/beemdevelopment/Aegis) on my
smartphone, I would not mind the convenience of not having to fetch my
phone when logging in to a service on my computer.

There are already a number of 2FA clients for Linux distributions:

* [OTPClient](https://github.com/paolostivanin/OTPClient)
* [GNOME Authenticator](https://gitlab.gnome.org/World/Authenticator)
* [pass-otp](https://github.com/tadfisher/pass-otp)
* [2fa](https://github.com/rsc/2fa)

`OTPClient` and `GNOME Authenticator` are GUI-based applications, while I am
looking for a command-line tool. `pass-otp` is a
[pass](https://www.passwordstore.org/) extension, but I do not use `pass`. `2fa`
is nice and minimal, but it doesn't encrypt the key-chain.
[Keepassxc](https://keepassxc.org/) also supports TOTP, but it is a graphical
tool.

I initially wanted to build an Aegis-compatible client, but I have decided
against that, owing to my desire to build a small, minimalist client. I will
likely support *importing* from Aegis in the future.

## License

FooTOTP (A command-line TOTP client for Unix-like systems.)

Copyright (C) 2021 Ajay R

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
