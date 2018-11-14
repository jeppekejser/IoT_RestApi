# READ ME

## SETUP

Make sure you have sqlite3 installed, this can be checked by running following command:
```
$ sqlite3 --version
```
If you have sqlite installed run following command:
```
$ sqlite3 api-database.db
```
Now get a ssl .key file and .cert file, make sure you have openssl installed by running following command:
```
$ openssl
```
If this command works, you should have openssl installed, now run following commands to create key and cert file:
```
$ openssl genrsa 1024 > ssl.key
$ openssl req -new -x509 -nodes -sha1 -days 365 -key ssl.key > ssl.cert
```
