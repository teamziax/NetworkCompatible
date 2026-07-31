package dev.kastle.netty.util.http;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import io.netty.util.internal.logging.InternalLogger;

import java.io.IOException;

/**
 * Log any web requests and their response codes and times to a given netty log
 */
public class LoggingHttpFilter extends Filter {

    private InternalLogger log;

    public LoggingHttpFilter(InternalLogger log) {
        this.log = log;
    }

    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        long start = System.nanoTime();
        chain.doFilter(exchange);
        long ms = (System.nanoTime() - start) / 1_000_000;

        log.debug("{} {} -> {} ({} ms)",
            exchange.getRequestMethod(),
            exchange.getRequestURI(),
            exchange.getResponseCode(),
            ms);
    }

    @Override
    public String description() {
        return "request-logging";
    }
}
