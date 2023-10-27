# TCP over QUIC
A very simple proxy that tunnels TCP connections through QUIC as a hacky solution for an unstable
connection.

This isn't a large serious project, as such very little effort if any will be put into maintaining
it. Please do not rely on this project. That being said, if you wish to improve this for whatever
reason, feel free to do so.

## Usage
```
Usage: tcp_over_quic <MODE> <RECEIVE_ADDRESS> <SEND_ADDRESS>

Arguments:
  <MODE>             [possible values: client, server]
  <RECEIVE_ADDRESS>  
  <SEND_ADDRESS>     

Options:
  -h, --help  Print help
```
