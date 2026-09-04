package dev.kastle.warden.admission;

import dev.kastle.netty.channel.nethernet.admission.*;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import org.cloudburstmc.netty.channel.raknet.RakChannelFactory;
import org.cloudburstmc.netty.channel.raknet.RakConstants;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import tel.schich.libdatachannel.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import static org.junit.jupiter.api.Assertions.*;

@Tag("native")
class NativeAdmissionIntegrationTest {
    @TempDir Path directory;
    NativeHostIdentity identity() throws Exception {
        Path cert = directory.resolve("host.crt"), key = directory.resolve("host.key");
        Process p = new ProcessBuilder("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key.toString(), "-out", cert.toString(), "-days", "1", "-subj", "/CN=public-test-only").redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(p.waitFor(10, TimeUnit.SECONDS));assertEquals(0,p.exitValue());
        return NativeHostIdentity.load(cert,key);
    }
    static void await(BooleanSupplier check) throws Exception {
        long end = System.nanoTime()+TimeUnit.SECONDS.toNanos(12);
        while (!check.getAsBoolean() && System.nanoTime()<end) Thread.sleep(10);
        assertTrue(check.getAsBoolean());
    }
    static void rakPing(int port) throws Exception {
        try(var socket = new DatagramSocket()) {
            socket.setSoTimeout(2000);
            byte[] ping=ByteBuffer.allocate(33).put((byte)1).putLong(12345).put(RakConstants.DEFAULT_UNCONNECTED_MAGIC).putLong(42).array();
            socket.send(new DatagramPacket(ping,ping.length,InetAddress.getByName("127.0.0.1"),port));
            byte[] reply=new byte[2048];var packet=new DatagramPacket(reply,reply.length);socket.receive(packet);
            assertEquals(port,packet.getPort());assertEquals(0x1c,reply[0]);assertEquals(12345,ByteBuffer.wrap(reply).getLong(1));
        }
    }
    @Test @Timeout(45) void noControlLazyJoinBothChannelsReplayAndCleanup() throws Exception {
        var id = identity(); var loopback = InetAddress.getByName("127.0.0.1"); int port = 49190;
        var validator = new StatelessAdmissionValidator(FakeWarden.AUDIENCE,60_000);
        validator.installKeys(List.of(new StatelessAdmissionValidator.TicketKey("K001",FakeWarden.SECRET)));
        var group = new DefaultEventLoopGroup(2);
        var rakGroup = new NioEventLoopGroup(1);
        Channel rak = new ServerBootstrap().group(rakGroup).channelFactory(RakChannelFactory.server(NioDatagramChannel.class))
            .childHandler(new ChannelInboundHandlerAdapter()).bind("127.0.0.1",49191).sync().channel();
        var endpoint = new NativeAdmissionServerChannel(id,validator,new AdmissionGate.Limits(4,8,2,10_000));
        AtomicInteger inboundMask = new AtomicInteger(); AtomicReference<AdmittedNetherNetChildChannel> child = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        ServerBootstrap bootstrap = new ServerBootstrap().group(group).channelFactory(() -> endpoint).childHandler(new ChannelInitializer<AdmittedNetherNetChildChannel>() {
            @Override protected void initChannel(AdmittedNetherNetChildChannel ch) {
                child.set(ch);
                ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                    boolean reliable = true;
                    @Override public void userEventTriggered(ChannelHandlerContext ctx,Object event) { if(event instanceof NetherNetPacket.Delivery d) reliable=d.reliable(); }
                    @Override protected void channelRead0(ChannelHandlerContext ctx,ByteBuf data) {
                        inboundMask.getAndUpdate(mask -> mask | (reliable?1:2));
                        // Nonzero reader index catches the old transport offset bug.
                        ByteBuf echo=ctx.alloc().buffer(data.readableBytes()+3).writeZero(3).writeBytes(data);echo.skipBytes(3);
                        ctx.writeAndFlush(new NetherNetPacket(echo,reliable));
                    }
                    @Override public void exceptionCaught(ChannelHandlerContext ctx,Throwable error) { failure.compareAndSet(null,error);ctx.close(); }
                });
            }
        });
        try {
            bootstrap.bind(new InetSocketAddress(loopback,port)).sync();rakPing(49191);
            assertEquals(0,endpoint.nativeStats()[2]);assertEquals(0,endpoint.admissionStats().claims());
            long beforeInvalid=PeerConnection.nativeCreationAttempts();
            try(var noise=new DatagramSocket()) { byte[] packet=new byte[40];noise.send(new DatagramPacket(packet,packet.length,loopback,port)); }
            await(()->endpoint.admissionStats().invalid()>0);
            assertEquals(beforeInvalid,PeerConnection.nativeCreationAttempts());assertEquals(0,endpoint.nativeStats()[3]);
            assertThrows(IllegalStateException.class,()->new RawUdpMuxListener(loopback,port,(p,a,n)->false));
            try(PeerConnection client=PeerConnection.createPeer(PeerConnectionConfiguration.DEFAULT.withDisableAutoNegotiation(true).withBindAddress(loopback),Runnable::run)) {
                CountDownLatch echoed = new CountDownLatch(2);List<DataChannel> channels=new ArrayList<>();
                for(int index=0;index<2;index++) {
                    boolean reliable=index==0;String label=reliable?"ReliableDataChannel":"UnreliableDataChannel";
                    DataChannel dc=client.createDataChannel(label,DataChannelInitSettings.DEFAULT.withReliability(new DataChannelReliability(!reliable,!reliable,0,0)));
                    channels.add(dc);var decoder=new NetherNetFrameDecoder();byte[] payload=new byte[reliable?20013:7];Arrays.fill(payload,(byte)(reliable?11:22));
                    dc.onMessage.register(DataChannelCallback.Message.handleBinary((d,buffer)->{
                        byte[] frame=new byte[buffer.remaining()];buffer.get(frame);
                        try { byte[] message=decoder.decode(frame,reliable);if(message!=null) {assertArrayEquals(payload,message);echoed.countDown();} }
                        catch(Throwable error){failure.compareAndSet(null,error);}
                    }));
                    dc.onOpen.register(d->{
                        int chunks=(payload.length+9998)/9999;
                        for(int i=0;i<chunks;i++) {int count=Math.min(9999,payload.length-i*9999);ByteBuffer frame=ByteBuffer.allocateDirect(count+1);frame.put((byte)(chunks-i-1)).put(payload,i*9999,count).flip();d.sendMessage(frame);}
                    });
                }
                client.setLocalDescription("offer","clientFixtureUf","p".repeat(32));
                var answer=FakeWarden.answer(client.localDescription(),id.fingerprint(),port,System.currentTimeMillis()+30_000,FakeWarden.AUDIENCE,false);
                var expired=FakeWarden.answer(client.localDescription(),id.fingerprint(),port,System.currentTimeMillis()-1_000,FakeWarden.AUDIENCE,false);
                var wrongHost=FakeWarden.answer(client.localDescription(),id.fingerprint(),port,System.currentTimeMillis()+30_000,"sig_fixture/gs_two/test_boot_001",false);
                String altered=answer.token().substring(0,80)+(answer.token().charAt(80)=='A'?'B':'A')+answer.token().substring(81);
                List<byte[]> rejectedPackets=List.of(
                    StatelessAdmissionValidatorTest.binding(expired.token()+":clientFixtureUf",expired.password()),
                    StatelessAdmissionValidatorTest.binding(wrongHost.token()+":clientFixtureUf",wrongHost.password()),
                    StatelessAdmissionValidatorTest.binding(altered+":clientFixtureUf",answer.password()),
                    StatelessAdmissionValidatorTest.binding(answer.token()+":clientFixtureUf","wrong-stun-integrity-password"),
                    StatelessAdmissionValidatorTest.binding(answer.token()+":differentClientUfrag",answer.password()));
                long beforeNegatives=PeerConnection.nativeCreationAttempts(), rejectedBefore=endpoint.admissionStats().invalid();
                try(var invalid=new DatagramSocket()) {
                    for(byte[] packet:rejectedPackets) invalid.send(new DatagramPacket(packet,packet.length,loopback,port));
                }
                await(()->endpoint.admissionStats().invalid()>=rejectedBefore+rejectedPackets.size());
                assertEquals(beforeNegatives,PeerConnection.nativeCreationAttempts());
                assertEquals(0,endpoint.admissionStats().claims());assertEquals(0,endpoint.nativeStats()[2]);assertEquals(0,endpoint.nativeStats()[3]);

                // Issuing an answer changes NO host state. Host has only its profile and key snapshot.
                assertEquals(0,endpoint.admissionStats().claims());assertEquals(0,endpoint.creationAttempts());
                long beforeJoin=PeerConnection.nativeCreationAttempts();
                client.setRemoteDescription(answer.sdp(),SessionDescriptionType.ANSWER);
                assertTrue(echoed.await(12,TimeUnit.SECONDS), "both channels echo through Netty");
                assertNull(failure.get());assertEquals(3,inboundMask.get());
                assertEquals(1,endpoint.creationAttempts());assertEquals(beforeJoin+1,PeerConnection.nativeCreationAttempts());rakPing(49191);
                assertEquals(1,endpoint.nativeStats()[2]);assertEquals(1,endpoint.nativeStats()[3]);
                try(var replay=new DatagramSocket()) {
                    byte[] packet=StatelessAdmissionValidatorTest.binding(answer.token()+":clientFixtureUf",answer.password());
                    replay.send(new DatagramPacket(packet,packet.length,loopback,port));
                    await(()->endpoint.admissionStats().replayRejected()>0);
                }
                assertEquals(1,endpoint.creationAttempts());assertEquals(1,endpoint.nativeStats()[3]);
                assertTrue(endpoint.pollEvents().stream().allMatch(e->e.validationToCreationNanos()>0));
                child.get().close().sync();
                await(()->endpoint.admissionStats().sessions()==0);
                assertEquals(0,child.get().queuedFrames());assertEquals(0,child.get().retainedAssemblyBytes());
            }
            endpoint.close().sync();endpoint.termination().toCompletableFuture().get(5,TimeUnit.SECONDS);
            try(var reuse=new DatagramSocket(new InetSocketAddress(loopback,port))) { assertEquals(port,reuse.getLocalPort()); }
            System.out.println("native-adapter PASS fixedUdp=49190 hostCreations=1 channels=3 replayRejected=true perJoinControl=0 cleanup=true raknetPong=49191");
        } finally { endpoint.close().awaitUninterruptibly();rak.close().awaitUninterruptibly();group.shutdownGracefully(0,2,TimeUnit.SECONDS).sync();rakGroup.shutdownGracefully(0,2,TimeUnit.SECONDS).sync(); }
    }
}
