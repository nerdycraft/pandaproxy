"""Tests for StreamFanout broadcast functionality."""

import asyncio

import pytest

from pandaproxy.fanout import StreamClient, StreamFanout


class TestStreamClient:
    """Tests for StreamClient class."""

    def test_init_creates_queue(self):
        """Client should have an async queue."""
        client = StreamClient("test_client")
        assert client.client_id == "test_client"
        assert client.connected is True
        assert client.queue is not None

    @pytest.mark.asyncio
    async def test_send_adds_to_queue(self):
        """Send should add data to the queue."""
        client = StreamClient("test")
        result = await client.send(b"test data")
        assert result is True
        assert client.queue.qsize() == 1

    @pytest.mark.asyncio
    async def test_send_returns_false_when_disconnected(self):
        """Send should return False when client is disconnected."""
        client = StreamClient("test")
        client.disconnect()
        result = await client.send(b"test data")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_drops_data_when_queue_full(self):
        """Send should drop data when queue is full (maxsize=100)."""
        client = StreamClient("test")
        # Fill the queue to capacity (default maxsize=100)
        for i in range(100):
            await client.send(f"data{i}".encode())
        # Queue is now full
        result = await client.send(b"overflow")
        # Should return False (dropped)
        assert result is False
        assert client.queue.qsize() == 100

    @pytest.mark.asyncio
    async def test_receive_gets_data(self):
        """Receive should return queued data."""
        client = StreamClient("test")
        await client.send(b"test data")

        data = await client.receive()
        assert data == b"test data"

    @pytest.mark.asyncio
    async def test_receive_returns_none_on_disconnect(self):
        """Receive should return None when disconnected."""
        client = StreamClient("test")
        client.disconnect()

        data = await client.receive()
        assert data is None

    def test_disconnect_sets_connected_false(self):
        """Disconnect should set connected to False."""
        client = StreamClient("test")
        assert client.connected is True

        client.disconnect()
        assert client.connected is False


class TestStreamFanout:
    """Tests for StreamFanout class."""

    def test_init_creates_empty_fanout(self):
        """Fanout should start with no clients."""
        fanout = StreamFanout("test_fanout")
        assert fanout.name == "test_fanout"
        assert fanout.client_count == 0
        assert fanout.is_running is False

    def test_start_sets_running(self):
        """Start should set is_running to True."""
        fanout = StreamFanout("test")
        fanout.start()
        assert fanout.is_running is True

    def test_stop_clears_running(self):
        """Stop should set is_running to False."""
        fanout = StreamFanout("test")
        fanout.start()
        fanout.stop()
        assert fanout.is_running is False

    @pytest.mark.asyncio
    async def test_register_client_adds_client(self):
        """Register should add a client and return it."""
        fanout = StreamFanout("test")
        fanout.start()

        client = await fanout.register_client("client1")

        assert client is not None
        assert client.client_id == "client1"
        assert fanout.client_count == 1

    @pytest.mark.asyncio
    async def test_register_multiple_clients(self):
        """Should support multiple clients."""
        fanout = StreamFanout("test")
        fanout.start()

        client1 = await fanout.register_client("c1")
        client2 = await fanout.register_client("c2")
        client3 = await fanout.register_client("c3")

        assert fanout.client_count == 3
        assert client1.client_id == "c1"
        assert client2.client_id == "c2"
        assert client3.client_id == "c3"

    @pytest.mark.asyncio
    async def test_unregister_client_removes_client(self):
        """Unregister should remove client from fanout."""
        fanout = StreamFanout("test")
        fanout.start()

        client = await fanout.register_client("client1")
        assert fanout.client_count == 1

        await fanout.unregister_client(client)
        assert fanout.client_count == 0

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all_clients(self):
        """Broadcast should send data to all registered clients."""
        fanout = StreamFanout("test")
        fanout.start()

        client1 = await fanout.register_client("c1")
        client2 = await fanout.register_client("c2")

        await fanout.broadcast(b"broadcast data")

        # Both clients should have received the data
        data1 = await asyncio.wait_for(client1.receive(), timeout=1.0)
        data2 = await asyncio.wait_for(client2.receive(), timeout=1.0)

        assert data1 == b"broadcast data"
        assert data2 == b"broadcast data"

    @pytest.mark.asyncio
    async def test_broadcast_returns_success_count(self):
        """Broadcast should return number of successful sends."""
        fanout = StreamFanout("test")
        fanout.start()

        await fanout.register_client("c1")
        await fanout.register_client("c2")

        count = await fanout.broadcast(b"data")
        assert count == 2

    @pytest.mark.asyncio
    async def test_broadcast_handles_list_data(self):
        """Broadcast should handle list of data chunks."""
        fanout = StreamFanout("test")
        fanout.start()

        client = await fanout.register_client("c1")

        await fanout.broadcast([b"chunk1", b"chunk2"])

        data = await asyncio.wait_for(client.receive(), timeout=1.0)
        assert data == [b"chunk1", b"chunk2"]

    @pytest.mark.asyncio
    async def test_stop_disconnects_all_clients(self):
        """Stop should disconnect all clients."""
        fanout = StreamFanout("test")
        fanout.start()

        client1 = await fanout.register_client("c1")
        client2 = await fanout.register_client("c2")

        fanout.stop()

        assert client1.connected is False
        assert client2.connected is False

    @pytest.mark.asyncio
    async def test_broadcast_skips_disconnected_clients(self):
        """Broadcast should skip disconnected clients."""
        fanout = StreamFanout("test")
        fanout.start()

        client1 = await fanout.register_client("c1")
        await fanout.register_client("c2")  # Second client needed for count

        client1.disconnect()

        count = await fanout.broadcast(b"data")
        # Only client2 should receive
        assert count == 1

    @pytest.mark.asyncio
    async def test_broadcast_when_not_running(self):
        """Broadcast should handle not-running state gracefully."""
        fanout = StreamFanout("test")
        # Don't start

        await fanout.register_client("c1")  # Register but don't use
        count = await fanout.broadcast(b"data")

        # Behavior depends on implementation - just verify no crash
        assert count >= 0
