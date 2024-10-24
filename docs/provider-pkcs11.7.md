% provider-pkcs11(7) | Configuration directives

NAME
====
pkcs11-provider - An OpenSSL provider that allows to directly interface
with pkcs11 drivers.


DESCRIPTION
===========

Starting with version 3.0 the OpenSSL project introduced a new modular
system to extend OpenSSL that replaces the deprecated Engines modules.

Providers(1) are loaded via configuration directives in the openssl
configuration file (or directly loaded by applications).

The pkcs11 provider allows applications linked to openssl to use keys
and cryptographic operations from a hardware or software token via
their PKCS#11(2) driver and the use of pkcs11 URIs(3).

The pkcs11 provider can be configured to be automatically loaded via
openssl.cnf


CONFIGURATION
=============
Configuration options recognized by the provider

## pkcs11-module-path

A file path to the pkcs11 driver to be used

Default: If compiled with p11-kit defaults to its proxy driver, otherwise none.

NOTE: See also PKCS11_PROVIDER_MODULE in the environment variables section.

Example:

```pkcs11-module-path = /usr/lib64/opensc-pkcs11.so```

## pkcs11-module-init-args

Non-standard initialization arguments some pkcs11 driver may need.
Generally not used, but some software tokens like NSS's softokn require
this.

Default: None

Example:

```pkcs11-module-init-args = configDir=/etc/pki/token```

## pkcs11-module-token-pin

The user PIN to be used with the token.
If a PIN is not set in configuration it can be asked interactively (if
the application uses prompters), or it can be specified together with
the key identifiers in the pkcs11 URI directly.
When a file is specified the file must be a text file containing just
the PIN on the first line and a \n terminator.

Default: None

Example:

```pkcs11-module-token-pin = file:/etc/pki/pin.txt```
```
cat /etc/pki/pin.txt
123456
```

## pkcs11-module-allow-export

Whether the pkcs11 provider will allow to export public keys through
OpenSSL.
OpenSSL often tries to export public keys from non-default providers to
the default provider, and then use OpenSSL own functions to handle
whatever operation is associated with the public key.
This option can be useful to force public key operations to be executed
on the token, for example in case the pkcs11 is an accelerator that has
better performance on signature checking or asymmetric encryption than
OpenSSL's code.

Default: 0 (Allow Export)

Example:

```pkcs11-module-allow-export = 1```
(This disallows export of public keys)

## pkcs11-module-cache-keys
Whether the pkcs11-provider should ask the token to cache token keys in
the session. This is used in some tokens as a performance optimizations.
For example software tokens that store keys encrypted can keep a copy of
the key in the session to speed up access.
Or Networked HSMs that allow exporting key material can cache the key in
the session instead of re-requesting it over the network.

Two options are available:
* true
* false

Default: true
(Note: if the token does not support session caching, then caching will
be auto-disabled after the first attempt)

Example:

```pkcs11-module-cache-keys = false```
(Disable any attempt of caching keys in the session)

## pkcs11-module-cache-pins
Whether the pkcs11-provider should cache a pin entered interactively.
This is useful to allow starting a service and providing the pin only
manually, yet let the service perform multiple logins as needed, for
example after forking.

Only one option is currently available:
* cache: Caches the PIN

Default: unset
(No caching)

Example:

```pkcs11-module-cache-pins = cache```
(Will cache a pin that has been entered manually)

## pkcs11-module-cache-sessions
Allows to tune how many pkcs11 sessions may be kept open and cached for
rapid use. This parameter is adjusted based on the maximum number of
sessions the token declares as supported. Note that the login session is
always cached to keep the token operable.

Default: 5

Example:

```pkcs11-module-cache-sessions = 0```
(Disables caching)

## pkcs11-module-login-behavior
Whether the pkcs11 provider will attempt to login to the token when a
public key is being requested.

Three options are available:
* auto: Try without but fallback to login behavior if no keys are found
* always: Always login before trying to load public keys (this is required by some HSMs)
* never: Never login for public keys

Default: "auto"

Example:

```pkcs11-module-login-behavior = always```
(Always tries to login before loading public keys)

## pkcs11-module-load-behavior
Whether the pkcs11-provider immediately loads an initializes the pkcs11
module as soon as OpenSSL loads the provider (generally at application
startup), or defer initialization until the first time a pkcs11 key is
loaded (or some other operation explicitly requiring the pkcs11 provider
is requested).

Only one option is available:
* early: Loads the pkcs11 module immediately

Default: unset
(Loads only at first use)

Example:

```pkcs11-module-load-behavior = early```
(Loads pkcs11 module immediately at application startup)

## pkcs11-module-quirks
Workarounds that may be needed to deal with some tokens and cannot be
autodetcted yet are not appropriate defaults.

### no-deinit
It prevents de-initing when OpenSSL winds down the provider.
NOTE this option may leak memory and may cause some modules to
misbehave if the application intentionally unloads and reloads them.

### no-operation-state
OpenSSL by default assumes contexts with operations in flight can be
easily duplicated. That is only possible if the tokens support getting
and setting the operation state. If the quirk is enabled the context
duplication is not performed.

### no-session-callbacks
Some implementatations of PKCS11 don't allow setting `pApplication` and
`Notify` callback functions in `C_OpenSession`.
This option sets NULL values for both callbacks.

### no-allowed-mechanisms
Some implementatations of PKCS11 don't support `CKA_ALLOWED_MECHANISMS`
attribute on keys. Setting this quirk prevents the provider from
attempting to set and read this attribute.

Default: none

Example:

```pkcs11-module-quirks = no-deinit no-operation-state```
(Disables deinitialization, blocks context duplication)

## pkcs11-module-block-operations
Allows to block specific "provider operations" even if the token actually
supports the necessary mechanisms. This is useful to work around cases
where one wants to enforce use of the token for all operations by setting
?provider=pkcs11 in the default properties but wants an exception for a
specific type of operation like digests.
NOTE: some operations may depend on others or may be fundamental to the
correct working of the provider, so not all configurations of this
parameter will work. Use carefully.

Default: none

Example:
```pkcs11-module-block-operations = digest```
(Disables digest mechanisms, which will be instead routed to the OpenSSL
default provider in most configurtions)


ENVIRONMENT VARIABLES
=====================
Environment variables recognized by the provider

## PKCS11_PROVIDER_MODULE

This variable can be used to set a different pkcs11 driver to be used.
It is useful when an application needs to use a different driver than
the rest of the system. This environment variable **overrides** the
pkcs11-module-path option sets in openssl.cnf

Example:

```PKCS11_PROVIDER_MODULE = /usr/lib64/opensc-pkcs11.so```

## PKCS11_PROVIDER_DEBUG

This variable can be set to obtain debug information.
Two sub-options can be specified: file, level

The normal debug_level is 1, if a higher level is provider then
additional information (like all supported mechanism info for each slot)
is printed in the specified debug file. The comma character separates
options, and the colon character is used to separate an option and its
value. There is no escape character, therefore the characters ',' and
':' cannot be used in values.

Examples:

```PKCS11_PROVIDER_DEBUG=file:/tmp/debug.log```

```PKCS11_PROVIDER_DEBUG=file:/dev/stderr,level:2```


USE IN OLDER APPLICATIONS (URIs in PEM files)
=============================================

It is strongly suggested to update applications to use the new
OSSL_STORE API provided by OpenSSL 3.0 which accepts URIs to
transparenly load keys from either files or any other supported
mechanism including PKCS#11 URIs.

However, for those applications that cannot yet be changed, there is
tool to generate a "wrapper" PEM file that contains the PKCS#11 URI
needed to identify a key on the a token.

This PEM file can be loaded via the clasic methods used to parse
PEM/DER representations of keys and will trigger the use of the
pkcs11-provider decoders when the provider is loaded. An error will be
returned if the provider is not pre-loaded or an older version of
OpenSSL is used.

In tools/uri2pem.py there is a sample python script that can take a key
URI and produce a PEM file that references it. Note that storing PINs
within these PEM files is not secure. These files are not encrypted.

The follwing command can be used to list all keys on a token and print
their identifying URI:

    openssl storeutl -keys -text pkcs11:


EXAMPLES
========

openssl.cnf:

    HOME = .
    
    # Use this in order to automatically load providers.
    openssl_conf = openssl_init
    
    [openssl_init]
    providers = provider_sect
    
    [provider_sect]
    default = default_sect
    pkcs11 = pkcs11_sect
    
    [default_sect]
    activate = 1
    
    [pkcs11_sect]
    module = /usr/lib64/ossl-modules/pkcs11.so
    pkcs11-module-path = /usr/lib64/pkcs11/vendor_pkcs11.so
    pkcs11-module-token-pin = /etc/ssl/pinfile.txt
    activate = 1


SEE ALSO
========

1. PROVIDER(7) man page - https://www.openssl.org/docs/manmaster/man7/provider.html

2. PKCS#11 Technical committe and standards - https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11

3. PKCS#11 URI Scheme - RFC 7512 - https://www.rfc-editor.org/rfc/rfc7512
