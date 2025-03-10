package com.blautech.ecommerce.gateway.filters;

import com.blautech.ecommerce.gateway.dtos.CheckResponse;
import com.blautech.ecommerce.gateway.dtos.PermissionRequest;
import com.blautech.ecommerce.gateway.dtos.TokenRequest;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {
    private final WebClient.Builder webClientBuilder;
    public AuthFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, HttpStatus.BAD_REQUEST);
            }
            String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                return onError(exchange, HttpStatus.BAD_REQUEST);
            }
            String[] chunks = authorization.split(" ");
            if (chunks.length != 2 || !chunks[0].equals("Bearer")) {
                return onError(exchange, HttpStatus.BAD_REQUEST);
            }
            String token = chunks[1];
            PermissionRequest permission = PermissionRequest.builder()
                .path(exchange.getRequest().getPath().value())
                .method(exchange.getRequest().getMethod().name())
                .build();
            TokenRequest tokenRequest = TokenRequest.builder()
                .token(token)
                .permission(permission)
                .build();
            return webClientBuilder.build()
                .post()
                .uri("http://authentication-microservice/api/v1/auth")
                .bodyValue(tokenRequest)
                .retrieve()
                .bodyToMono(CheckResponse.class)
                .map(checkResponse -> {
                    System.out.println("Success: " + checkResponse.getSuccess());
                    return exchange;
                }).flatMap(chain::filter);
        });
    }
    public Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }
    public static class Config {

    }
}
