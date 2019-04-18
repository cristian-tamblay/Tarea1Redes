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
In case you want to use custom values for both port, resolver and cache expiration (in seconds) type:
```shell
$ python3 server.py --port [port] --resolver_dns [DNS RESOLVER] --expiration [EXPIRATION]
```

Once the server is up and running you can shut it down with Ctrl+C
## Cache

The server store a cache in Cache.txt file. This is a binary file made by the serialization of the dictionary object.
Upon expiration, the server wipes the Cache.txt file.

## Filter Configuration

The server provides an API to give default responses or no response (filtered domains).
You can use your favorite text editor to create a Filters.txt list which will be read on initialization of the server.

The list can handle pairs URL IP, or URL forbidden, just as shown in Filters.txt provided.

If the URL is forbidden, no IP will be shown in dig and a beautiful warning: Warning: Message parser reports malformed message packet.
If the URL has a filtered IP and multiple answers, only the first one will be filtered (intended)
## Contact

In case of fire, git commit and send email to dpalma@dcc.uchile.cl and cristian.tamblay@ing.uchile.cl
