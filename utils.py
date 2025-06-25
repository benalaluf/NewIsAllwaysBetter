
    
def parse_bytes(data: bytes):
    offset = 0
    request = yield
    while True:
        if (request > 0):
            chunk = data[offset: offset + request]
            offset += request
        else:
            chunk = data[offset: request]
        request = yield chunk

if __name__ == "__main__":
    a = parse_bytes(b"\xff"*3+b"\xaa"*3)
    next(a)
    print(a.send(3))
    print(a.send(3))