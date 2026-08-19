package dev.kastle.netty.channel.nethernet.config;

import io.netty.channel.ChannelOption;
import tel.schich.libdatachannel.PeerConnectionConfiguration;

public class NetherChannelOption<T> extends ChannelOption<T> {

    /**
     * The {@link PeerConnectionConfiguration} used for the underlying peer connections.
     * <p>
     * ICE servers supplied by the signaling implementation are merged into this at connect time, and
     * auto-negotiation is always forced off because the channels drive the offer/answer exchange
     * themselves - so setting either of those here has no effect.
     * <p>
     * Note that {@code withPortRangeBegin}/{@code withPortRangeEnd} take a signed {@code short}, so
     * ports above 32767 need an explicit narrowing cast, e.g. {@code (short) 60000}. The value is
     * reinterpreted as an unsigned 16-bit port natively, so this works as intended.
     */
    public static final ChannelOption<PeerConnectionConfiguration> NETHER_PEER_CONNECTION_CONFIG =
            valueOf(NetherChannelOption.class, "NETHER_PEER_CONNECTION_CONFIG");

    /**
     * The timeout in seconds for completing the WebRTC handshake on the client before retrying.
     */
    public static final ChannelOption<Integer> NETHER_CLIENT_HANDSHAKE_TIMEOUT_MS =
            valueOf(NetherChannelOption.class, "NETHER_CLIENT_HANDSHAKE_TIMEOUT_MS");

    /**
     * The maximum number of handshake attempts before giving up on connecting.
     */
    public static final ChannelOption<Integer> NETHER_CLIENT_MAX_HANDSHAKE_ATTEMPTS =
            valueOf(NetherChannelOption.class, "NETHER_CLIENT_MAX_HANDSHAKE_ATTEMPTS");

     /**
     * The timeout in seconds for completing the WebRTC handshake on the server side before automatically closing the connection.
     */
    public static final ChannelOption<Integer> NETHER_SERVER_RTC_HANDSHAKE_TIMEOUT_SECONDS =
            valueOf(NetherChannelOption.class, "NETHER_SERVER_RTC_HANDSHAKE_TIMEOUT_SECONDS");

    @SuppressWarnings("deprecation")
    protected NetherChannelOption(String name) {
        super(name);
    }
}
