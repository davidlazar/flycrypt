flycrypt
========

Quickly encrypt strings.

Install
-------

    go get github.com/davidlazar/flycrypt

Generate key pair
-----------------

```
$ flycrypt 
[k]ey  [e]nc  [d]ec: k

 Public key: r9za5ncqfb5ab6e6py1kpwe7fqrf3rsrx4cc6ax2tvwt2c0ce4bg
Private key: eef3tyy2ggfmhagtg1ewcsakx5qzerng7dwbdjgscrgx20fbn290 (SAVE THIS)
```
Avoid reusing keys.

Encrypt
-------

```
$ flycrypt
[k]ey  [e]nc  [d]ec: e
Public key: r9za5ncqfb5ab6e6py1kpwe7fqrf3rsrx4cc6ax2tvwt2c0ce4bg
>> Message (^D to finish):
hello world

-- Ciphertext --
g97qgx8sqng0rv7zm5jq3hjnhj650fq3dn56cmjkjz0spb8c7sv60xycx9a48z0k1g3kbpbd0wnq586n4wy7wtc4n6y8vadb01ff5sejvhvj2
```


Decrypt
-------

```
$ flycrypt
[k]ey  [e]nc  [d]ec: d
Private key: eef3tyy2ggfmhagtg1ewcsakx5qzerng7dwbdjgscrgx20fbn290
>> Ciphertext (^D to finish):
g97qgx8sqng0rv7zm5jq3hjnhj650fq3dn56cmjkjz0spb8c7sv60xycx9a48z0k1g3kbpbd0wnq586n4wy7wtc4n6y8vadb01ff5sejvhvj2

-- Message --
hello world
```

Caveats
-------

flycrypt does not protect against man-in-the-middle attacks.
