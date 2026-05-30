package com.example.apigateway.filter;

import com.example.apigateway.security.JwtService;

import io.jsonwebtoken.Claims;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.cloud.gateway.filter.GlobalFilter;

// este componente funciona automaticamente porque implementa el Global Filter, lo que significa que
// va pasar por este componente siempre que se ejecuten todos los request
@Component
public class JwtAuthenticationFilter implements GlobalFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        String path = exchange.getRequest()
                .getURI()
                .getPath();

        if (path.startsWith("/api/auth")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null ||
                !authHeader.startsWith("Bearer ")) {

            return onError(exchange, "Token missing");
        }

        String token = authHeader.substring(7);

        boolean valid = jwtService.isTokenValid(token);

        if (!valid) {
            return onError(exchange, "Invalid token");
        }
        
        Claims claims = jwtService.extractClaims(token);

        String username = claims.getSubject();

        String role = claims.get("role", String.class);

        ServerWebExchange modifiedExchange =
                exchange.mutate()
                        .request(r -> r
                                .header("X-User", username)
                                .header("X-Role", role)
                        )
                        .build();

        return chain.filter(modifiedExchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange,
                               String message) {

        ServerHttpResponse response =
                exchange.getResponse();

        response.setStatusCode(HttpStatus.UNAUTHORIZED);

        DataBuffer buffer = response.bufferFactory()
                .wrap(message.getBytes());

        return response.writeWith(Mono.just(buffer));
    }
}