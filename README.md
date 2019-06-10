### Jacob Allen's Python Twitter

#### Prerequisites:
- Python3. This can be checked by running `python --version` in terminal.
- Pip3. This can be checked by running `pip3 --version` in terminal. (Tested using v9.0.1)
- Install permissions

## First Time Install Instructions
- Open a new Terminal window `ctrl + alt + t` and enter the following commands:
- `pip3 install cherrypy`
- `pip3 install jinja2`
- `pip3 install pynacl`

## Launch Instructions
- Navigate to the root directory of this project
- Open a new Terminal window `ctrl + alt + t`
- Run the command `python3 main.py`

## Connecting to the Server
- Open your favorite browser and navigate to the connection_url listed in the terminal window.
(This wil have "Serving on 'connection_url')
- To Login, fill out the required fields
  - Username = University UPI
  - Password = GitHub_Username _ University_ID
  - Select a key type:
    - Encryption Key = The password used to encrypt / decrypt private data
    - Private Key = Your private key that has been registered with the login server
    
    
- Alternitavly create a new private key pair
  - Username = University UPI
  - Password = GitHub_Username _ University_ID
  - Encryption Key = The password that will be used to encrypt your private data
