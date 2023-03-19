# asip_proxy

This SIP proxy is composed in pure java script. A simple registrar service wuth authentication is in place.

## configuration

The SIP proxy is prepared to configure generic parameters and to load an static account data. The json files
are located in data folder.

## build & run

```
npm install
```

if using pm2 framework

```
pm2 start pm2.config.js

```

else

```
  node src/server.js
```

## notes

Currently only default generic parameters are used:

- port        : 5060
- transport: udp
