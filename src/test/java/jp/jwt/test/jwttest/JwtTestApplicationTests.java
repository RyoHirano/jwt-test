package jp.jwt.test.jwttest;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.security.Keys;

@SpringBootTest
class JwtTestApplicationTests {
	private static final String SUBJECT = "test";
	private static final String AUTH_ALGORITHM = "HS256";

	private String jws;
	private byte[] secretKeyBytes;

	@BeforeEach
	void createJws() {
		secretKeyBytes = createSecretKeyBytes();
		jws = Jwts.builder()
				.setSubject(SUBJECT)
				.signWith(Keys.hmacShaKeyFor(secretKeyBytes)).compact();
	}

	@Test
	void jwtSuccess() {
		Jws<Claims> parsedJws = Jwts.parserBuilder()
									.setSigningKey(secretKeyBytes)
									.build()
									.parseClaimsJws(jws);
		assertAll("success", 
			() -> assertEquals(parsedJws.getBody().getSubject(), SUBJECT),
			() -> assertEquals(parsedJws.getHeader().getAlgorithm(), AUTH_ALGORITHM));
	}

	@Test
	void jwtFail() {
		Jws<Claims> parsedJws = Jwts.parserBuilder()
									.setSigningKey(secretKeyBytes)
									.build()
									.parseClaimsJws(jws);

		assertAll("fail", 
			() -> assertEquals(parsedJws.getBody().getSubject(),
								SUBJECT.substring(0, SUBJECT.length() - 1)),
			() -> assertEquals(parsedJws.getHeader().getAlgorithm(),
								AUTH_ALGORITHM.substring(0, AUTH_ALGORITHM.length() -1)));
	}

	private byte[] createSecretKeyBytes() {
		return UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
	}
}
