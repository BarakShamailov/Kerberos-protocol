# Kerberos-protocol
This project is an implementation of the basic version of the Kerberos protocol, the project is written in Python.

In this project, there are three entities: the client, the authenticator server and the message server.

The authenticator server is responsible for verifying users who want to access services from the message server.

The client wants to receive services from the message server.

The message server's purpose is to print messages that it receives from the client.

The project's purpose is to study Kerberos protocol and cyber security fundmentals such as: symmetric encryption, exploits and more.

Question 2 involves the implementation of an offline dictionary attack on the protocol, along with a suggestion to prevent this attack.
## Architecture
![image](https://github.com/BarakShamailov/Kerberos-protocol/assets/62948065/c430e276-2c02-4fd9-8bf4-4522c63216e4)
![image](https://github.com/BarakShamailov/Kerberos-protocol/assets/62948065/251160cc-8bdb-4dd3-a267-ede68a2dfe26)

## Installtions Instructions:
1. Install PyCryptodome:
   ```bash
   > pip install pycryptodome
   ```
2. Place the files that are located in Q1 folder in your IDE.

## How to use ?
1. Run the authenticator_server.py.
2. Run the messages_server.py.
3. Run the client.py.
