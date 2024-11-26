package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Configuration
public class JwtTokenUtility {

    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring.security.jwt.expiration-time}")
    private long jwtExpiration;

    private final Logger logger = LoggerFactory.getLogger(JwtTokenUtility.class);

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(HttpServletRequest header) {
        if(header.getHeader("Role").equalsIgnoreCase("user")){
            long nowMillis = System.currentTimeMillis();
            long expMillis = nowMillis + 3600000; // 1 hour in milliseconds
            Date exp = new Date(expMillis);
            System.out.println("EXP: "+ exp);
            String jwt = Jwts.builder()
                    .subject(header.getHeader("Role"))
                    .claim("role", "user")
                    .issuedAt(new Date(nowMillis))
                    .signWith(getSignInKey())
                    .expiration(exp)
                    .compact();
            return jwt;
        }else{
            long nowMillis = System.currentTimeMillis();
            long expMillis = nowMillis + 3600000; // 1 hour in milliseconds
            Date exp = new Date(expMillis);
            System.out.println("EXP: "+ exp);
            String jwt = Jwts.builder()
                    .subject(header.getHeader("Role"))
                    .claim("role", "admin")
                    .issuedAt(new Date(nowMillis))
                    .signWith(getSignInKey())
                    .expiration(exp)
                    .compact();
            return jwt;
        }

    }

    public boolean isTokenValid(String token) {
        return isTokenExpired(token);
//        try {
//            Jwts.parserBuilder()
//                    .setSigningKey(getSignInKey())
//                    .build()
//                    .parseClaimsJws(token);
//            return true;
//        } catch (Exception e) {
//            logger.error("Token validation failed: {}", e.getMessage());
//            return false;
//        }
//        final String username = extractUsername(token);
//        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        boolean isTokenExpired = extractExpiration(token).before(new Date());
        if(isTokenExpired){
            logger.error("Error: Expired Token");
            return false;
        }else {
            return true;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().build().parseSignedClaims(token).getPayload();
//        return Jwts.parserBuilder()
//                .setSigningKey(getSignInKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
