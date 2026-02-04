## Installation

First run the command `docker-compose build` to build the docker images

Then, run the command `docker-compose up` to start up the server and two client images

## Usage

Use `docker ps --format "{{.ID}} {{.Names}}"` command to show the ID and name for the online containers.

Then use `docker exec -it <id> /bin/bash` or `docker exec -it <id> /bin/sh` to enter the container. 

The server side will automatically run after the docker container is online. 

Use `python3 client.py` to run the program on the client side.


### Client Commands

After run the client program, you can use `help` or `h` will show the help menu.

`register` or `r` will register a new account.

`login` or `l` will log in as the existing account.

`message` or `m` can send the message to another user.

`view` or `v` can have a look at the message history stored locally.

`delete` or `d` can delete the message history with another user.

`logout` or `u` can log out the current account.

`quit` or `q` can exit the program safely.

