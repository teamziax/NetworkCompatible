package dev.kastle.warden.admission;

import dev.kastle.netty.channel.nethernet.admission.*;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class AdmissionGateTest extends AdmissionFixture {
    final InetSocketAddress first = new InetSocketAddress("127.0.0.1", 23450), other = new InetSocketAddress("127.0.0.1", 23451);
    final byte[] valid = binding(token + ":" + remote, password);
    AdmissionGate gate() { return new AdmissionGate(new AdmissionGate.Limits(2, 2, 1, 1000), validator()); }
    @Test void invalidTrafficHasNoReservationsOrQueuedWork() {
        var gate = gate(); var work = new ArrayBlockingQueue<AdmissionGate.Reservation>(1);
        for (int i = 0; i < 1000; i++) assertFalse(gate.ingress(binding(token + ":" + remote, "wrong-password-000000000000"), first, now, 0, work::add));
        assertEquals(0, gate.stats().sessions()); assertEquals(0, gate.stats().claims()); assertTrue(work.isEmpty());
        assertEquals(1000, gate.stats().invalid());
    }
    @Test void concurrentRetransmitsCreateOnlyOneAndConflictingTupleCannotClaim() throws Exception {
        var gate = gate(); var work = new ArrayBlockingQueue<AdmissionGate.Reservation>(1);
        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Callable<Boolean>> calls = new ArrayList<>();
            for (int i = 0; i < 64; i++) calls.add(() -> gate.ingress(valid, first, now, 0, work::add));
            for (Future<Boolean> result : executor.invokeAll(calls)) assertFalse(result.get());
        }
        assertEquals(1, work.size()); assertEquals(1, gate.stats().accepted());
        var r = work.remove(); assertFalse(gate.ingress(valid, other, now, 0, work::add));
        assertEquals(1, gate.stats().replayRejected()); assertTrue(gate.ready(r)); gate.connected(r);
        assertTrue(gate.ingress(valid, first, now + 120_000, 120_000_000_000L, work::add));
        assertEquals(0, gate.sweep(now + 120_000, 120_000_000_000L).size());
        assertEquals(1, gate.stats().claims()); // active consent is not expiry eviction
        assertTrue(gate.finish(r)); assertNull(gate.admission(r));
        assertFalse(gate.ingress(valid, first, now, 0, work::add)); // failed/closed cannot allocate again
        assertEquals(1, gate.stats().claims());
        gate.sweep(now + 120_000, 120_000_000_000L); assertEquals(0, gate.stats().claims());
    }
    @Test void timeoutCapacityQueueFailureAndCloseAreTerminal() {
        var gate = gate(); var work = new ArrayBlockingQueue<AdmissionGate.Reservation>(1);
        gate.ingress(valid, first, now, 0, work::add); var r = work.remove();
        assertEquals(List.of(r), gate.sweep(now + 1000, 1_000_000_000));
        assertFalse(gate.ready(r)); assertNull(gate.admission(r)); assertEquals(0, gate.stats().pending());
        gate.close();assertEquals(0, gate.stats().claims());
        assertFalse(gate.ingress(valid, first, now, 0, work::add));assertTrue(work.isEmpty());
        var failed = gate(); failed.ingress(valid, first, now, 0, ignored -> { throw new RejectedExecutionException(); });
        assertEquals(0, failed.stats().sessions()); assertEquals(1, failed.stats().claims());
        assertFalse(failed.ingress(valid, first, now, 0, work::add)); assertTrue(work.isEmpty());
        var drained = gate(); drained.drain();assertFalse(drained.ingress(valid, first, now, 0, work::add));assertEquals(0, drained.stats().claims());
    }
}
