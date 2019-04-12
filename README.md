# Tarea1Redes

## Prerequisites

 * Python3
 * A client to send DNS requests (you can use **dig**)

## Running the code

To start the server run (depending on your plaform)
```shell
$ python3 server.py
```
This will make the server run on *port 8001* and send the requests to the resolver *8.8.8.8*.
You can type `$ python3 server.py -h` to get help.
In case you want to use custom values for both port and resolver type:
```shell
$ python3 server.py --port [port] --resolver_dns [DNS RESOLVER]
```

Once the server is up and running you can shut it down with Ctrl+C

## Filter Configuration

The server provides an API to give default responses or no response (filtered domains).
You can use your favorite text editor to create a filter.txt list which will be read on initialization of the server.

The list ...


## Contact

In case of fire, git commit and send email to dpalma@dcc.uchile.cl and cristian.tamblay@ing.uchile.cl

## TODO

Verificar que las IDs coincidan en la tarea