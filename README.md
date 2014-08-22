Ntunnel
=======

Simple tunnel protocol with RSA keys, signed digests and blowfish cipher using the OpenSSL library and the tuntap device from the Linux kernel and its API.

## How to generate keys:

Ntunnel use RSA keys, you'll have to create a pair on the server and on every client.

```
openssl genrsa -out PRIVATE_KEY.pem 1024
openssl rsa -in PRIVATE_KEY.pem -pubout > PUBLIC_KEY.pem
```

* Save the PRIVATE key and don't share it with anyone.
* If you're running a server, you'll have to share your PUBLIC key with every client.
* If you're running a client, you'll have to share your PUBLIC key with the server owner so he set up a connection for you in that server.

## How to run the server:

```
./server/ntunnel conf_server.ini
```

If you don't know how to configure the server, take a look at the example configuration [here](https://github.com/nomius/ntunnel/blob/master/example/conf_server.ini)

## How to run the client:

```
./client/ntunnel conf_client.ini conf1
```

Where ```conf1``` is the section name holding the configuration in the conf_client.ini file.
If you don't know how to configure the client, take a look at the example configuration
[here](https://github.com/nomius/ntunnel/blob/master/example/conf_client1.ini)
