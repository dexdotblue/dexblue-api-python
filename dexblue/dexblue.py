import time
import pkgutil
import json
import ssl
import asyncio
import websockets
import time
from web3.auto import w3
from eth_account.messages import encode_defunct
from web3 import Web3


class WsAPI:
    def __init__(self, endpoint="wss://api.dex.blue/ws", network="mainnet", web3Provider="https://mainnet.infura.io/", account=None, delegate=None, autoAuth=True):
        self.utils = Utils()
        self.methods = Methods(self, self.utils)

        self._ws = None

        self.account = account
        self.delegate = delegate

        self.websocketAddress = endpoint
        self.network = network
        self.web3Provider = web3Provider

        self.contractAddress = None
        self.listed = None
        self.tokensByContract = None

        self._callbacks = {}
        self._ridCount = 0
        self._stop = False

        self.connect(account, delegate, autoAuth)

    def connect(self, account=None, delegate=None, autoAuth=True):
        asyncio.ensure_future(
            self._starter(account, delegate, autoAuth))

    def close(self):
        asyncio.ensure_future(self._close())

    def authenticate(self, privateKey, callback=None, *args, **kwargs):
        nonce = self.utils.getNonce()
        msg = f"Authenticate {nonce}"
        message = encode_defunct(text=msg)
        signedMessage = w3.eth.account.sign_message(
            message, private_key=privateKey)

        packet = [{"c": "authenticate",
                   "message": msg,
                   "nonce": nonce,
                   "signature": Web3.toHex(signedMessage["signature"])
                   }]

        if callback:
            rid = self._newRID()
            self._setCallback(rid, callback, *args, **kwargs)
            packet[0]["rid"] = rid

        self._sendWrapper(packet)

    def authenticateDelegate(self, privateKey, callback=None, *args, **kwargs):
        nonce = self.utils.getNonce()
        msg = f"Authenticate {nonce}"
        message = encode_defunct(text=msg)
        signedMessage = w3.eth.account.sign_message(
            message, private_key=privateKey)

        packet = [{"c": "authenticateDelegate",
                   "message": msg,
                   "nonce": nonce,
                   "signature": Web3.toHex(signedMessage["signature"])
                   }]

        if callback:
            rid = self._newRID()
            self._setCallback(rid, callback, *args, **kwargs)
            packet[0]["rid"] = rid

        self._sendWrapper(packet)
    def _cbPlaceOrder(self, packet, parameters, callback=None, *args, **kwargs):
        self.placeOrder(parameters, callback, *args, **kwargs)

    def placeOrder(self, parameters, callback=None, *args, **kwargs):
        if not self.contractAddress:
            self.utils.error("Contract Adress not set. Not connected yet?")

        if not self.listed:
            self.methods.getListed(None, self._cbPlaceOrder, parameters, callback)
            return

        if "market" in parameters:
            cm = parameters["market"] = self.listed["listed"]["markets"][parameters["market"]]
            if not cm:
                self.utils.error("Unkown Token")
        else:
            if not "buyToken" in parameters or not "sellToken" in parameters:
                self.utils.error("Please provide either the market or the buyToken and sellToken parameters")

            if parameters["buyToken"] in self.tokensByContract:
                buyToken = self.tokensByContract[parameters["buyToken"]]
            elif parameters["buyToken"] in self.listed["listed"]["tokens"]:
                buyToken = self.listed["listed"]["tokens"][parameters["buyToken"]]
            else:
                self.utils.error("Unknown buy token")
            
            if parameters["sellToken"] in self.tokensByContract:
                sellToken = self.tokensByContract[parameters["sellToken"]]
            elif parameters["sellToken"] in self.listed["listed"]["tokens"]:
                sellToken = self.listed["listed"]["tokens"][parameters["sellToken"]]
            else:
                self.utils.error("Unknown sell token")

            if not buyToken or not sellToken:
                self.utils.error("Unknown token")

            parameters["sellToken"] = sellToken["contract"]
            parameters["buyToken"] = buyToken["contract"]
            
            buy = buyToken["symbol"] + sellToken["symbol"] in self.listed["listed"]["markets"]
            sell = sellToken["symbol"] + buyToken["symbol"] in self.listed["listed"]["markets"]
            if buy:
                parameters["market"] = self.listed["listed"]["markets"][buyToken["symbol"] + sellToken["symbol"]]
                parameters["direction"] = "buy"
            elif sell:
                parameters["market"] = self.listed["listed"]["markets"][sellToken["symbol"] + buyToken["symbol"]]
                parameters["direction"] = "sell"
            else:
                self.utils.error("Unknown market")

        if "amount" in parameters:
            parameters["amount"] = parameters["amount"] * pow(10, self.listed["listed"]["tokens"][parameters["market"]["traded"]]["decimals"])
        
        if not "direction" in parameters:
            if "side" in parameters:
                parameters["direction"] = parameters["side"]
            elif "amount" in parameters:
                parameters["direction"] = "buy" if parameters["amount"] > 0 else "sell"

        if "amount" in parameters and parameters["amount"] < 0:
            parameters["amount"] = parameters["amount"] * -1

        if not "buyToken" in parameters or not "sellToken" in parameters:
            if parameters["direction"] == "buy":
                parameters["buyToken"] = self.listed["listed"]["tokens"][parameters["market"]["traded"]]["contract"]
                parameters["sellToken"] = self.listed["listed"]["tokens"][parameters["market"]["quote"]]["contract"]
            else:
                parameters["buyToken"] = self.listed["listed"]["tokens"][parameters["market"]["quote"]]["contract"]
                parameters["sellToken"] = self.listed["listed"]["tokens"][parameters["market"]["traded"]]["contract"]
        
        if not "buyAmount" in parameters or not "sellAmount" in parameters:
            if not "amount" in parameters or not "rate" in parameters:
                self.utils.error("Please the amount and rate or buyAmount and sellAmount parameters")
            
            if parameters["direction"] == "buy":
                parameters["buyAmount"] = parameters["amount"]
                parameters["sellAmount"] = parameters["amount"] / pow(10, self.listed["listed"]["tokens"][parameters["market"]["traded"]]["decimals"]) * parameters["rate"] * pow(10, self.listed["listed"]["tokens"][parameters["market"]["quote"]]["decimals"])
            else:
                parameters["sellAmount"] = parameters["amount"]
                parameters["buyAmount"] = parameters["amount"] / pow(10, self.listed["listed"]["tokens"][parameters["market"]["traded"]]["decimals"]) * parameters["rate"] * pow(10, self.listed["listed"]["tokens"][parameters["market"]["quote"]]["decimals"])

        parameters["nonce"] = self.utils.getNonce()
        parameters["buyAmount"] = str(int(parameters["buyAmount"]))
        parameters["sellAmount"] = str(int(parameters["sellAmount"]))
        parameters["market"] = parameters["market"]["symbol"]

        try:
            del parameters["amount"]
        except:
            pass
        try:
            del parameters["direction"]
        except:
            pass
        try:
            del parameters["rate"]
        except:
            pass
        try:
            del parameters["side"]
        except:
            pass

        if not "expiry" in parameters:
            parameters["expiry"] = int(time.time()) + 5184000 # default 3 months


        msg = {}

        if not "signature" in parameters and (self.account or self.delegate):
            privateKey = ""
            if self.account != None:
                privateKey = self.account
            elif self.delegate != None:
                privateKey = self.delegate

            orderHash = self.utils.hashOrder(
                parameters["sellToken"],
                int(parameters["sellAmount"]),
                parameters["buyToken"],
                int(parameters["buyAmount"]),
                parameters["expiry"],
                parameters["nonce"],
                self.contractAddress
            )

            message = encode_defunct(hexstr=orderHash)
            signedMessage = w3.eth.account.sign_message(
                message, private_key=privateKey)

            
            for param in parameters:
                msg[param] = parameters[param]

            msg["signature"] = Web3.toHex(signedMessage["signature"])
            msg["signatureFormat"] = "sign"

            self.utils.validateClientMethods("placeOrder", msg)

        msg["c"] = "placeOrder"
        packet = [msg]

        if callback:
            rid = self._newRID()
            self._setCallback(rid, callback, *args, **kwargs)
            packet[0]["rid"] = rid

        self._sendWrapper(packet)

    def on(self, event, callback, *args, **kwargs):
        if self.utils.validateServerEventName(event):
            self._setCallback(event, callback, args, kwargs)

    def clear(self, event):
        if self._hasCallback(event):
            self._removeCallback(event)

    def once(self, event, callback, *args, **kwargs):
        self.utils.validateServerEventName(event)

        # set user callback and _removeCallback
        callbacks = [{"cb": callback, "args": args, "kwargs": kwargs}, {
            "cb": lambda msg, event: self.clear(event), "args": (event, ), "kwargs": {}}]
        self._setCallback(event, callbacks)

    def _setContractAdress(self, connectMessage):
        if isinstance(connectMessage, dict):
            if "config" in connectMessage:
                self.contractAddress = connectMessage["config"]["contractAddress"]

    def _setNetworkFromConfig(self, connectMessage):
        if isinstance(connectMessage, dict):
            if "config" in connectMessage:
                self.network = connectMessage["config"]["network"]

    def _setListed(self, listedMessage):
        if isinstance(listedMessage, dict):
            if "listed" in listedMessage:
                self.listed = listedMessage
                self.tokensByContract = {}

                for symbol in listedMessage["listed"]["tokens"]:
                    token = listedMessage["listed"]["tokens"][symbol]
                    token["symbol"] = symbol
                    self.tokensByContract[token["contract"]] = token
                
                for symbol in self.listed["listed"]["markets"]:
                    self.listed["listed"]["markets"][symbol]["symbol"] = symbol

    async def _starter(self, account=None, delegate=None, autoAuth=True):
        self._stop = False  # when true this this var stops the listener
        self._ridCount = 0

        connectTask = asyncio.ensure_future(
            self._connect(account, delegate, autoAuth))
        self._listenerTask = asyncio.ensure_future(
            self._listener())
        done, pending = await asyncio.wait(
            [connectTask, self._listenerTask],
            return_when=asyncio.ALL_COMPLETED,)

    async def _listener(self):
        while not self._isCon():
            await asyncio.sleep(0.01)

        while self._isCon() and not self._stop:
            packet = await self._recv()
            asyncio.ensure_future(self._packetHandler(packet))

    def _isCon(self):
        if not self._ws or self._ws.closed:
            return False
        return True

    def _newRID(self):
        self._ridCount += 1
        return self._ridCount

    def _removeCallback(self, identifier):
        self._callbacks.pop(identifier)

    def _setCallback(self, identifier, callback, *args, **kwargs):
        callbacks = []

        if isinstance(callback, list):
            callbacks += callback
        else:
            callbacks.append({"cb": callback, "args": args, "kwargs": kwargs})

        if self._hasCallback(identifier):
            cb = self._getCallback(identifier)
            callbacks += cb

        self._callbacks[str(identifier)] = callbacks

    def _getCallback(self, identifier):
        if not identifier == None and identifier in self._callbacks:
            return self._callbacks[identifier]

    def _hasCallback(self, identifier):
        if identifier in self._callbacks:
            return True
        return False

    def _callback(self, identifier, data):
        callbacks = self._getCallback(str(identifier))

        for obj in callbacks:
            kwargs = obj["kwargs"]
            args = obj["args"]

            if isinstance(args, tuple) and len(args) > 0:
                if isinstance(args[0], tuple):
                    args = obj["args"][0]

            if (not args and not kwargs) or ((args == ((), {}) or args == (((), {}), {})) and not kwargs):
                obj["cb"](data)
            elif args and kwargs:
                obj["cb"](data, *args, **kwargs)
            elif args and not kwargs:
                obj["cb"](data, *args)
            else:
                obj["cb"](data, **kwargs)

    def _callbackWrapper(self, packet, identifier, message):
        # throws the packet away and just calls the callback
        if self._hasCallback(identifier):
            self._callback(identifier, message)

    def _throwIfNoCon(self):
        if not self._isCon():
            self.utils.error("WebSocket isn't connected.")

    async def _connect(self, account=None, delegate=None, autoAuth=True):
        self.on("listed", self._setListed)
        callbacks = [{"cb": self._setContractAdress, "args": (), "kwargs": {}}, {
            "cb": self._setNetworkFromConfig, "args": (), "kwargs": {}}]

        self._setCallback("config", callbacks)
        self._ws = await websockets.connect(self.websocketAddress, ssl=ssl._create_unverified_context())

        if autoAuth and (account or delegate):
            if account:
                self.authenticate(account,
                                  self._callbackWrapper, "wsOpen", None)
            else:
                self.authenticateDelegate(delegate,
                                          self._callbackWrapper, "wsOpen", None)
        else:
            self._callback("wsOpen", None)

    def _sendWrapper(self, msg):
        asyncio.ensure_future(self._send(msg))

    async def _send(self, msg):
        jsonDump = json.dumps(msg)

        if self._hasCallback("wsSend"):
            self._callback("wsSend", msg)

        if not self._isCon() or self._stop:
            if self._hasCallback("wsClose"):
                self._callback("wsClose", msg)

        await self._ws.send(jsonDump)

    async def _recv(self):
        try:
            packet = await self._ws.recv()

            if self._hasCallback("message"):
                self._callback("message", packet)

        except Exception as e:
            print(f"Couldn't receive message because of {e}")
            if "connection is closed" in str(e) and self._hasCallback("wsClose"):
                self._callback("wsClose", "died on recv")
            return

        return packet

    async def _close(self):
        self._ws.close()
        self._stop = True
        print("Connection closed by API!")

    async def _packetHandler(self, packet):
        if packet == "[]" or not packet:
            return

        parsedPacket = self._parsePacket(packet)

        for message in parsedPacket:
            eventId = str(message[1])
            event = self.utils.matchServerEvent(eventId)

            if len(message) == 4:
                rid = str(message[3])

                if self._hasCallback(rid):
                    parsedServerEvent = {"chan": message[0], event: self.utils.parseServerPacket(
                        self.utils.serverEvents["events"][event], message[2]), "packet": message}
                    self._callback(rid, parsedServerEvent)

            eventId = message[1]
            if event and self._hasCallback(event):
                parsedServerEvent = {"chan": message[0], event: self.utils.parseServerPacket(
                    self.utils.serverEvents["events"][event], message[2]), "packet": message}
                self._callback(event, parsedServerEvent)

    def _parsePacket(self, packet):
        packet = json.loads(packet)
        if not isinstance(packet, list):
            self.utils.error("Received Package was malformed!")

        return packet


class Methods:
    def __init__(self, api, utils):
        self.api = api
        self.utils = utils

        self._setMethods()

    def _make_method(self, name):
        def _method(parameters=None, callback=None, *args, **kwargs):
            packet = [{"c": name}]

            if parameters and isinstance(parameters, dict):
                self.utils.validateClientMethods(name, parameters)
                for param in parameters:
                    packet[0][param] = parameters[param]

            if callback:
                rid = self.api._newRID()
                self.api._setCallback(rid, callback, *args, **kwargs)
                packet[0]["rid"] = rid

            self.api._sendWrapper(packet)

        return _method

    def _setMethods(self):
        for name in self.utils.clientMethods:
            _method = self._make_method(name)
            setattr(self, name, _method)


class Utils:
    def __init__(self):
        self.clientMethods = self._readJsonConfig("config/clientMethods.json")
        self.serverEvents = self._readJsonConfig("config/serverEvents.json")

    @staticmethod
    def _readJsonConfig(jsonFile):
        return json.loads(pkgutil.get_data(__package__, jsonFile))

    def validateClientMethods(self, method, parameters):
        if not method in self.clientMethods:
            self.error(f"Method doesn't exist: {method}")

        if "c" in parameters:
            del parameters["c"]

        methodObj = self.clientMethods[method]

        if not parameters:
            if methodObj == {}:
                return True

            for attr in methodObj:
                if not "optional" in attr:
                    self.error(
                        f"Parameter '{attr}' in command '{method}' should be set!")

        for attr in methodObj:
            if not "optional" in methodObj[attr] and not attr in parameters:
                self.error(
                    f"Parameter '{attr}' in command '{method}' should be set!")

        for param in parameters:
            if not param in methodObj:
                self.error(
                    f"Parameter '{param}' in command '{method}' shouldn't exist! Maybe your parameter name is wrong or your API Version is outdated.")

            supposedType = methodObj[param]["type"]
            actualValue = parameters[param]
            fullAttrName = f"{method}['{param}']"
            self.checkType(supposedType, actualValue, fullAttrName)

            if "length" in methodObj[param]:
                supposedLength = methodObj[param]['length']
                actualLength = len(parameters[param])

                self.checkLength(supposedLength, actualLength, fullAttrName)

        return True

    def validateServerEventName(self, eventName):
        _manualEvents = ["wsClose", "wsOpen"]
        if eventName in self.serverEvents["events"] or eventName in _manualEvents:
            return True
        self.error(
            f"Server event '{eventName}' doesn't exist. Check spelling and the documentation.")

    def matchServerEvent(self, eventId):
        for event in self.serverEvents["events"]:
            if self.serverEvents["events"][event]["id"] == eventId:
                return event
        self.error(
            f"Got server packet with non existing eventId: {eventId}")

    def parseServerPacket(self, defObject, packet):
        primitiveTypes = ["string", "hexString", "bool", "binbool", "float",
                          "floatString", "int", "uint", "uintString", "intString"]

        if defObject["type"] in primitiveTypes:
            if not packet == None:
                self.checkType(defObject["type"], packet, defObject)

            return packet

        if defObject["type"] == "array":
            if "fields" in defObject:
                parsedObject = dict()
                pos = 0

                if len(packet) < 1:
                    return {}

                for field in defObject["fields"]:
                    parsedObject[field["name"]] = self.parseServerPacket(
                        field, packet[pos])
                    pos += 1

                return parsedObject

            elif "elements" in defObject:
                parsedObject = []

                for pack in packet:
                    parsedObject.append(self.parseServerPacket(
                        defObject["elements"], pack))

                return parsedObject

        elif defObject["type"] == "object":
            parsedObject = dict()

            if "keys" in defObject:
                for key in defObject["keys"]:
                    if "optional" in defObject["keys"][key] and not key in packet:
                        parsedObject[key] = None
                    else:
                        parsedObject[key] = self.parseServerPacket(
                            defObject["keys"][key], packet[key])

                return parsedObject

            elif "elements" in defObject:
                for element in packet:
                    parsedObject[element] = self.parseServerPacket(
                        defObject["elements"], packet[element])

                return parsedObject

        elif defObject["type"] == "struct":
            return self.parseServerPacket(self.serverEvents["structs"][defObject["struct"]], packet)

    def checkLength(self, supLength, length, name):
        if not supLength == length:
            self.error(f"Length of {name} should be {supLength}")

        return True

    @staticmethod
    def getNonce():
        return int(str(time.time_ns())[:-6])

    def checkType(self, attrType, value, name):
        if attrType == "uint" and not isinstance(value, int):
            self.error(
                f"Type of parameter {name} should be int and not: {type(value)}")
        if attrType == "string" and not isinstance(value, str):
            self.error(
                f"Type of parameter {name} should be str and not: {type(value)}")
        if attrType == "hexString" and not isinstance(value, str):
            self.error(
                f"Type of parameter {name} should be str and not: {type(value)}")
        if attrType == "bool" and not isinstance(value, bool):
            self.error(
                f"Type of parameter {name} should be bool and not: {type(value)}")
        if attrType == "uintString" and not isinstance(value, str):
            self.error(
                f"Type of parameter {name} should be str and not: {type(value)}")
        if attrType == "floatString" and not isinstance(value, str):
            self.error(
                f"Type of parameter {name} should be floatString and not: {type(value)}")
        if attrType == "object" and not isinstance(value, dict):
            self.error(
                f"Type of parameter {name} should be dict and not: {type(value)}")

    @staticmethod
    def hashOrder(sellTokenAdress, sellTokenAmount, buyTokenAdress, buyTokenAmount, expiry, nonce, contractAdress):
        hashTypes = [
            'address',
            'uint128',
            'address',
            'uint128',
            'uint32',
            'uint64',
            'address'
        ]
        hashData = [
            w3.toChecksumAddress(sellTokenAdress),
            sellTokenAmount,
            w3.toChecksumAddress(buyTokenAdress),
            buyTokenAmount,
            expiry,
            nonce,
            w3.toChecksumAddress(contractAdress)
        ]

        orderHash = w3.soliditySha3(hashTypes, hashData)

        return Web3.toHex(orderHash)

    @staticmethod
    def hashMessage(types, msg):
        msgHash = w3.soliditySha3(types, msg)
        return Web3.toHex(msgHash)

    @staticmethod
    def signMessage(message, privateKey):
        return w3.eth.account.signHash(message, private_key=privateKey)

    @staticmethod
    def signTransaction(transaction, privateKey):
        return w3.eth.account.signTransaction(transaction, privateKey)

    # FIXME
    # - EIP20_ABI NOT DEFINED
    # - INVOKE METHOD WRONG USAGE

    def singContractTransaction(self, transaction, privateKey, invokeMethod, contractAdress):
        contract = w3.eth.contract(address=contractAdress, abi=EIP20_ABI)
        nonce = int(round(time.time() * 1000))

        tx = contract.functions.invokeMethod(
            contractAdress, 1).buildTransaction(transaction)
        return self.signTransaction(transaction, privateKey)

    @staticmethod
    def sendRawTransaction(rawTransaction):
        return w3.eth.sendRawTransaction(rawTransaction)
        # FIXME CHECK ENCRYPTION OF KEY

    @staticmethod
    def readPrivateKeyFromFile(keyFilePath, password):
        with open(keyFilePath) as keyFile:
            encryptedKey = keyFile.read()
        return w3.eth.account.decrypt(encryptedKey, password)

    @staticmethod
    def error(errorMsg):
        raise Exception("An Error occured: " + errorMsg)
