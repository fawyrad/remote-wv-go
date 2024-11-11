# remote-wv-go

Serve your local Widevine CDM as remote API.

## Note
This repository does not promote piracy of any kind. This project was created for educational purpose ONLY. This repository does not provide any CDM (Content Decryption Module). You will need your own Widevine CDM to serve it as remote API.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

First: `cp env.example .env`

## MakeFile

Run build make command with tests
```bash
make all
```

Build the application
```bash
make build
```

Run the application
```bash
make run
```

Live reload the application:
```bash
make watch
```

Run the test suite:
```bash
make test
```

Clean up binary from the last build:
```bash
make clean
```

## Authentication

All routes are protected to prevent unauthorized access.

A default super_user with a passkey will be created in the database when the API runs
for the first time. Check db for passkey.

### User Types
Owner: Set both super_user and sudoer to 1.<br/>
Regular User: Only sudoer permission is needed (super_user can be 0).

### Permissions
0: False
1: True

### Fields:
super_user: 0 (no super user access) or 1 (super user access)<br/>
sudoer: 0 (no sudo access) or 1 (sudo access)

By default both `super_user` and `sudoer` field is set to 0.

## Routes

get callenge:
```
curl --location 'localhost:4000/v1/challenge' \
--header 'passkey: passkey' \
--header 'Content-Type: application/json' \
--data '{
    "pssh": "pass the pssh"
}'
```

get decryption key:
```
curl --location 'localhost:4000/v1/key' \
--header 'passkey: passkey' \
--header 'Content-Type: application/json' \
--data '{
    "license": "CAIS+license you get back from any site",
    "challenge": "CAES+ you received from the challenge route",
    "pssh": "pass the pssh again"
}'
```

get cached key:
```
curl --location 'localhost:4000/v1/arsenal/key' \
--header 'passkey: passkey' \
--header 'Content-Type: application/json' \
--data '{
    "pssh": "pass the pssh"
}'
```

## Super User routes
### passkey

generate:
```
curl --location 'http://localhost:8080/su/passkey' \
--header 'Content-Type: application/json' \
--header 'passkey: super_user_passkey' \
--data '{
    "sudoer": 1, // Default: 0  
    "super_user": 0, // Default: 0 (Super User is only for owner. Give permission wisely!) 
    "quantity": 5 // Default: 1
}`
```
returns an array of passkeys

revoke:

```
curl --location 'http://localhost:8080/su/revoke' \
--header 'Content-Type: application/json' \
--header 'passkey: super_user passkey' \
--data '{
    "passkey": "pass key to be revoked"
}'
```

## Credits
The bulk of the Widevine related code was taken from `chris124567/hulu`
