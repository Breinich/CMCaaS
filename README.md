# Confidential Model Checking as a Service (CMCaaS)

This repository contains a POC solution for a service, which makes confidential model checking available on a suitable platform.

## Client Software

To start the client, run the following command:
```
java RemoteClient
```

If the program is run in a standard terminal, it will detect the console and prompt for the following details.  
Press Enter to accept the default values shown in parentheses:
- **Service Host**: The IP address or hostname of the server (Default: localhost).
- **Service Port**: The port the server is listening on (Default: 8080).
- **Username**: The user’s login ID (Default: test).
- **Password**: The user’s secure password.
- **Filename**: The path to the compressed file to be verified (Default: ../../data/test.zip).
