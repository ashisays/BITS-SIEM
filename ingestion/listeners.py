"""
BITS-SIEM Syslog Listeners
Multi-protocol syslog ingestion (UDP, TCP, TLS)
"""

import asyncio
import logging
import ssl
import socket
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import structlog

from config import config, SyslogConfig
from parsers import parser, SyslogMessage
from enrichment import enricher

logger = structlog.get_logger(__name__)

class SyslogListener:
    """Base class for syslog listeners"""
    
    def __init__(self, listener_config: SyslogConfig, message_handler: Callable):
        self.config = listener_config
        self.message_handler = message_handler
        self.running = False
        self.stats = {
            'messages_received': 0,
            'bytes_received': 0,
            'processing_errors': 0,
            'start_time': None,
            'last_message_time': None
        }
    
    async def start(self):
        """Start the listener"""
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        logger.info(f"Starting {self.config.protocol.upper()} listener on {self.config.host}:{self.config.port}")
    
    async def stop(self):
        """Stop the listener"""
        self.running = False
        logger.info(f"Stopping {self.config.protocol.upper()} listener")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get listener statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['start_time'] = stats['start_time'].isoformat()
        if stats['last_message_time']:
            stats['last_message_time'] = stats['last_message_time'].isoformat()
        return stats
    
    async def process_message(self, raw_data: bytes, source_ip: str):
        """Process a received syslog message"""
        try:
            # Update statistics
            self.stats['messages_received'] += 1
            self.stats['bytes_received'] += len(raw_data)
            self.stats['last_message_time'] = datetime.utcnow()
            
            # Decode message
            raw_message = raw_data.decode('utf-8', errors='ignore').strip()
            
            # Parse message
            parsed_message = parser.parse(raw_message, source_ip)
            
            # Enrich message
            enriched_message = enricher.enrich_message(parsed_message)
            
            # Handle the message
            await self.message_handler(enriched_message)
            
        except Exception as e:
            self.stats['processing_errors'] += 1
            logger.error(f"Error processing message from {source_ip}: {e}")

class UDPSyslogListener(SyslogListener):
    """UDP syslog listener (RFC3164 traditional syslog)"""
    
    def __init__(self, listener_config: SyslogConfig, message_handler: Callable):
        super().__init__(listener_config, message_handler)
        self.transport = None
        self.protocol = None
    
    async def start(self):
        """Start UDP listener"""
        await super().start()
        
        try:
            loop = asyncio.get_running_loop()
            
            # Create UDP server
            self.transport, self.protocol = await loop.create_datagram_endpoint(
                lambda: UDPSyslogProtocol(self.process_message),
                local_addr=(self.config.host, self.config.port)
            )
            
            logger.info(f"UDP syslog listener started on {self.config.host}:{self.config.port}")
            
        except Exception as e:
            logger.error(f"Failed to start UDP listener: {e}")
            raise
    
    async def stop(self):
        """Stop UDP listener"""
        await super().stop()
        
        if self.transport:
            self.transport.close()
            await asyncio.sleep(0.1)  # Give time for cleanup

class UDPSyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages"""
    
    def __init__(self, message_processor):
        self.message_processor = message_processor
    
    def datagram_received(self, data: bytes, addr: tuple):
        """Handle received UDP datagram"""
        source_ip = addr[0]
        asyncio.create_task(self.message_processor(data, source_ip))

class TCPSyslogListener(SyslogListener):
    """TCP syslog listener (RFC6587 syslog over TCP)"""
    
    def __init__(self, listener_config: SyslogConfig, message_handler: Callable):
        super().__init__(listener_config, message_handler)
        self.server = None
        self.clients = set()
    
    async def start(self):
        """Start TCP listener"""
        await super().start()
        
        try:
            # Create TCP server
            self.server = await asyncio.start_server(
                self.handle_client,
                self.config.host,
                self.config.port
            )
            
            logger.info(f"TCP syslog listener started on {self.config.host}:{self.config.port}")
            
        except Exception as e:
            logger.error(f"Failed to start TCP listener: {e}")
            raise
    
    async def stop(self):
        """Stop TCP listener"""
        await super().stop()
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all client connections
        for client in self.clients.copy():
            client.close()
            await client.wait_closed()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle TCP client connection"""
        client_addr = writer.get_extra_info('peername')
        source_ip = client_addr[0] if client_addr else 'unknown'
        
        logger.info(f"New TCP connection from {source_ip}")
        self.clients.add(writer)
        
        try:
            while self.running:
                try:
                    # Read message (RFC6587 format)
                    # Messages can be framed with length prefix or line termination
                    data = await asyncio.wait_for(
                        reader.readuntil(b'\n'),
                        timeout=self.config.timeout
                    )
                    
                    if not data:
                        break
                    
                    await self.process_message(data, source_ip)
                    
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout reading from {source_ip}")
                    break
                except asyncio.IncompleteReadError:
                    logger.info(f"Client {source_ip} disconnected")
                    break
                    
        except Exception as e:
            logger.error(f"Error handling TCP client {source_ip}: {e}")
        finally:
            self.clients.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            logger.info(f"TCP connection closed for {source_ip}")

class TLSSyslogListener(SyslogListener):
    """TLS syslog listener (RFC5425 syslog over TLS)"""
    
    def __init__(self, listener_config: SyslogConfig, message_handler: Callable):
        super().__init__(listener_config, message_handler)
        self.server = None
        self.clients = set()
        self.ssl_context = None
    
    async def start(self):
        """Start TLS listener"""
        await super().start()
        
        try:
            # Create SSL context
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=config.tls_cert_path,
                keyfile=config.tls_key_path
            )
            
            # Create TLS server
            self.server = await asyncio.start_server(
                self.handle_client,
                self.config.host,
                self.config.port,
                ssl=self.ssl_context
            )
            
            logger.info(f"TLS syslog listener started on {self.config.host}:{self.config.port}")
            
        except Exception as e:
            logger.error(f"Failed to start TLS listener: {e}")
            raise
    
    async def stop(self):
        """Stop TLS listener"""
        await super().stop()
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all client connections
        for client in self.clients.copy():
            client.close()
            await client.wait_closed()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle TLS client connection"""
        client_addr = writer.get_extra_info('peername')
        source_ip = client_addr[0] if client_addr else 'unknown'
        
        logger.info(f"New TLS connection from {source_ip}")
        self.clients.add(writer)
        
        try:
            while self.running:
                try:
                    # Read message with length prefix (RFC5425)
                    # Format: <length> <message>
                    length_data = await asyncio.wait_for(
                        reader.readuntil(b' '),
                        timeout=self.config.timeout
                    )
                    
                    if not length_data:
                        break
                    
                    try:
                        message_length = int(length_data.strip())
                        if message_length > self.config.buffer_size:
                            logger.warning(f"Message too large from {source_ip}: {message_length} bytes")
                            break
                        
                        # Read the actual message
                        data = await asyncio.wait_for(
                            reader.readexactly(message_length),
                            timeout=self.config.timeout
                        )
                        
                        await self.process_message(data, source_ip)
                        
                    except (ValueError, asyncio.IncompleteReadError):
                        # Try fallback to newline-delimited format
                        reader_buffer = length_data + await asyncio.wait_for(
                            reader.readuntil(b'\n'),
                            timeout=self.config.timeout
                        )
                        await self.process_message(reader_buffer, source_ip)
                    
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout reading from {source_ip}")
                    break
                except asyncio.IncompleteReadError:
                    logger.info(f"TLS client {source_ip} disconnected")
                    break
                    
        except Exception as e:
            logger.error(f"Error handling TLS client {source_ip}: {e}")
        finally:
            self.clients.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            logger.info(f"TLS connection closed for {source_ip}")

class ListenerManager:
    """Manages all syslog listeners"""
    
    def __init__(self, message_handler: Callable):
        self.message_handler = message_handler
        self.listeners = {}
        self.tasks = {}
    
    def create_listeners(self):
        """Create all enabled listeners"""
        for listener_config in config.get_enabled_listeners():
            if listener_config.protocol == 'udp':
                listener = UDPSyslogListener(listener_config, self.message_handler)
            elif listener_config.protocol == 'tcp':
                listener = TCPSyslogListener(listener_config, self.message_handler)
            elif listener_config.protocol == 'tls':
                if config.is_tls_enabled():
                    listener = TLSSyslogListener(listener_config, self.message_handler)
                else:
                    logger.warning("TLS listener enabled but certificates not found, skipping")
                    continue
            else:
                logger.error(f"Unknown protocol: {listener_config.protocol}")
                continue
            
            self.listeners[listener_config.protocol] = listener
    
    async def start_all(self):
        """Start all listeners"""
        for protocol, listener in self.listeners.items():
            try:
                await listener.start()
                
                # For UDP, we need to keep the task running
                if protocol == 'udp':
                    self.tasks[protocol] = asyncio.create_task(self._keep_udp_running(listener))
                
            except Exception as e:
                logger.error(f"Failed to start {protocol} listener: {e}")
    
    async def stop_all(self):
        """Stop all listeners"""
        # Cancel tasks
        for task in self.tasks.values():
            task.cancel()
        
        # Stop listeners
        for listener in self.listeners.values():
            await listener.stop()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
    
    async def _keep_udp_running(self, listener: UDPSyslogListener):
        """Keep UDP listener running"""
        try:
            while listener.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all listeners"""
        return {
            protocol: listener.get_stats()
            for protocol, listener in self.listeners.items()
        }
