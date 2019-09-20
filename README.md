# dex.blue python api wrapper

This is the official Python API wrapper for communicating with the dex.blue API.

For further information head to the [API Documentation](https://docs.dex.blue)

## Installation

Install via [pip](https://pypi.org/project/dexblue-api/)

```bash
pip install dexblue-api
```

## Introduction

dex.blue is a trustless, non-custodial exchange. This means, that every input which moves funds needs to by signed with your private key.

 You either have to sign orders directly from your wallet address or use a [Delegated Signing Key](https://docs.dex.blue/delegation/).

For the most straightforward integration, which does not require you to directly interact with the blockchain, you can just use our [webinterface](https://dex.blue/trading) for deposits & withdrawals and register a [Delegated Signing Key](https://docs.dex.blue/delegation/) in the settings ⚙ section.

If you want to handle deposits and withdrawals from your bot, please check out [this page](https://docs.dex.blue/contract/) of our documentation.

## Basic example

```python
import dexblue

db = dexblue.WsAPI()

db.methods.getListed()

db.on('listed', print)
```

## Initializing a connection

Tha connection can be initialized with different parameters.

```python
import dexblue

db = dexblue.WsAPI(
    delegate=<DEXBLUE DELEGATE KEY>,
    account=<ETHEREUM PRIVATE KEY>,
    endpoint=<DEXBLUE WEBSOCKET ENDPOINT>, # default: wss://api.dex.blue/ws
    web3Provider=<ETHEREUM WEB3 RPC ENDPOINT>, # default: https://mainnet.infura.io/
    network=<ETHEREUM NETWORK>, # default: mainnet
    autoAuth=<AUTHENTICATE WHEN CONNECTION OPENS> # default: True
)

def callback(packet):
    # your code here

db.on('wsOpen', callback)
```

It is possible to use a encrypted key tho authenticate your connection

```python
key = dexblue.utils.readPrivateKeyFromFile(keyfile, password)

db = dexblue.WsAPI(delegate=key)
```

## Calling a method

This Library provides a wrapper function for [every method offered by the dex.blue API](https://docs.dex.blue/websocket/), which can be invoked with eg: `db.methods.getOrderBookSnapshot(parameters, callback, <callback arguments>...)`.

For a full list of the available methods and parameters, please refer to the [websocket API documentation](https://docs.dex.blue/websocket/).

Additionally the library offers some helper functions to deal with all of the hard and annoying stuff like hashing and signing:

- `db.authenticate(privKey)` - called automatically, when you pass an account to the constructor
- `db.authenticateDelegate(privKey)` - Called automatically, when you pass an delegate to the constructor
- `db.placeOrder(order, callback)` - This function abstracts all the stress of contructing and signing orders away from you. Very recommended to use this!
- `db.hashOrder(order) returns hash` - This function helps you hashing the order inputs correctly. You then need to sign the order by yourself.

### Events

You can subscribe to any server and websocket events using the following functions:

Events:

- Market Events:
  - `book20d5` ... `book20d1` Orderbook with a depth of 20 with 5 ... 1 decimal precision (for the rate)
  - `book100d5` ... `book100d1` Orderbook with a depth of 10 with 5 ... 1 decimal precision (for the rate)
  - `bookd5` ... `bookd1` Full orderbook with 5 ... 1 decimal precision (for the rate)
  - `trades` Trades Feed of the market
  - `ticker` The ticker of the market
- Other Events:
  - `rate` subscribe to a ETH to fiat conversion rate e.g. ETHUSD, available are ETH traded against the config.conversion_currencies. (sub with: `{markets:["ETHUSD"],events:["rate"]}`)
  - `chainStats` subscribe to the servers block height and gas price (sub with: `{markets:["ethereum"],events:["chainStats"]}`)
- Websocket Events (no need to subscribe, just listen)
  - `wsOpen` websocket connection is opened
  - `message` every received message
  - `wsError` websocket errored
  - `wsClose` websocket conn is closed

### Subscribing to events

```python
db.methods.subscribe({
    "markets" : ["ETHDAI", "MKRETH"],
    "events"  : ["trades", "book20d5"]
})

db.on('events', print)
```

### Callback

A callback must have at least one paramater which is the received data. The following arguments are passed through from the callback definition.

```python
def callback(packet, parameter1, parameter2, ...):
    print(packet, parameter1, parameter2)

db.on('listed', callback, "parameter1", "parameter2")
```

The packet parameter is a dict, which has the following structure

```python
{
    "chan": <CHANNEL>, # The channel id is documented in the dex.blue api docs
    <EVENT NAME>: <PARSED PACKET>,
    "packet": <UNPARSED PACKET> # the same packet which the server sent
}
```

### Placing an order

```python
def callback(packet):
    # If you passed an account of delegate to the constructor, you will authenticated automatically
    # All private commands should be sent after we are successfully authenticated
    # If no expiry is passed, a default expiry of one month will be applied

    # This function supports either very abstracted input
    db.placeOrder({
        "market" : "ETHDAI",
        "amount" : -1,        # positive amount implies buy order, negative sell
        "rate"   : 300
    }, print)

    # This function supports either very abstracted input
    orderIdentifier = int(time.time()) # client-set order identifier
    db.placeOrder({
        "cid"         : orderIdentifier,
        "sellToken"   : "0x0000000000000000000000000000000000000000",  # ETH
        "sellAmount"  : "1000000000000000000",                         # 1 ETH
        "buyToken"    : "0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359",  # DAI
        "buyAmount"   : "300000000000000000000",                       # 300 DAI
        "expiry"      : int(time.time() + 86400 * 2),     # order is valid 2 days (different from the timeInForce parameter)
        "hidden"      : False,
        "postOnly"    : True,     # order is either maker or canceled
        "rebateToken" : "buy",    # we want to receive our rebate in DAI (the token we buy)
        # ... more possibilities are listed here: https://docs.dex.blue/websocket/#placeorder
    }, print)

db.on('auth', callback)
```

### Error handeling

```python
def reconnect_cb(packet):
    print('Reconnect in: ' + str(packet["reconnect"]["timeout"]) + 's. Message: ' + packet["reconnect"]["message"])

db.on('reconnect', reconnect_cb) # server sent a reconnect instruction

db.on('error', print) # handle error (probably resulting in a disconnect)

db.on('wsClose', print) # handle disconnect
```
