from server import Server


server = Server(port=8000)
server._run_forever(False)