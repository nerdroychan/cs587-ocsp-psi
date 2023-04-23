import asyncio
import pickle

sessions = {}
lock = asyncio.Lock()


async def handle_thirdparty(reader, writer):
    data = await reader.read()
    msg = pickle.loads(data)
    session_id = msg[0]
    is_client = msg[1]

    print("Third-party Server received psi session {}".format(session_id))

    await lock.acquire()
    if not sessions.get(session_id):
        sessions[session_id] = {"crl_ready": asyncio.Event()}
    lock.release()

    if is_client:
        print("  - This is client")
        cert = msg[2]
        await lock.acquire()
        sessions[session_id]["cert"] = cert
        lock.release()
        # busy wait on crl
        await sessions[session_id]["crl_ready"].wait()
        if cert in sessions[session_id].get("crl"):
            writer.write(b"1")
        else:
            writer.write(b"0")
        writer.write_eof()
        await writer.drain()
    else:
        print("  - This is CA")
        crl = msg[2]
        await lock.acquire()
        sessions[session_id]["crl"] = crl
        sessions[session_id]["crl_ready"].set()
        lock.release()

        writer.write(b"1")
        writer.write_eof()
        await writer.drain()

    writer.close()
    await writer.wait_closed()


async def main():
    server = await asyncio.start_server(
        handle_thirdparty, "127.0.0.1", 23334)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f'OCSP Server running on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
