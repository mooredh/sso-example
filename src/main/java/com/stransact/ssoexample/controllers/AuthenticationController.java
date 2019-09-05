package com.stransact.ssoexample.controllers;

import com.stransact.ssoexample.config.JwtConfig;
import com.stransact.ssoexample.exceptions.ResourceNotFoundException;
import com.stransact.ssoexample.exceptions.UnauthorizedException;
import com.stransact.ssoexample.exceptions.ValidationException;
import com.stransact.ssoexample.models.*;
import com.stransact.ssoexample.repository.AccessTokenRepository;
import com.stransact.ssoexample.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * The type Authentication
 *
 * @author moore.dagogohart
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    public AuthenticationController(JwtConfig jwtConfig, UserRepository userRepository, AccessTokenRepository accessTokenRepository, BCryptPasswordEncoder passwordEncoder) {
        this.jwtConfig = jwtConfig;
        this.userRepository = userRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private final JwtConfig jwtConfig;
    private final UserRepository userRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * @param authId id
     * @return Response entity  success
     */
    @GetMapping("/{authId}")
    public ResponseEntity<SuccessResponse> getAuthUser(@PathVariable("authId") long authId, @RequestHeader("Authorization") String authToken) throws UnauthorizedException {
        authToken = authToken.substring(7);
        AccessToken accessToken = accessTokenRepository.findByToken(authToken);

        if (accessToken == null) throw new UnauthorizedException("UNAUTHORIZED");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = authentication.isAuthenticated();

        if (!isAuthenticated) throw new UnauthorizedException("UNAUTHORIZED");
        User user = (User) authentication.getPrincipal();

        if (user.getId() != authId) throw new UnauthorizedException("UNAUTHORIZED");

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("user", user);

        return ResponseEntity.ok(new SuccessResponse(HttpStatus.OK.toString(), responseData));
    }

    /**
     * @param request req
     * @return Response entity  success
     * @throws ResourceNotFoundException resource
     * @throws ValidationException validation
     */
    @PostMapping("/*")
    public ResponseEntity<SuccessResponse> createAuthToken(@Valid @RequestBody JwtRequest request) throws ResourceNotFoundException, ValidationException {
        User user = authenticate(request.getEmail(), request.getPassword());

        final String token = jwtConfig.generateToken(user, 24 * 60 * 60);
        final Date expiry = jwtConfig.getExpirationDateFromToken(token);

        AccessToken accessToken = new AccessToken();
        accessToken.setExpiry(expiry);
        accessToken.setToken(token);
        accessToken.setUser(user);

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("token", token);
        responseData.put("user", user);
        responseData.put("expiry", expiry);

        accessTokenRepository.save(accessToken);

        return ResponseEntity.ok(new SuccessResponse(HttpStatus.OK.toString(), responseData));
    }

    @DeleteMapping("/*")
    public ResponseEntity<SuccessResponse> deleteToken(@RequestHeader("Authorization") String authToken) throws UnauthorizedException {
        String oldAccessToken = authToken.substring(7);

        AccessToken accessToken = accessTokenRepository.findByToken(oldAccessToken);

        if (accessToken == null) {
            throw new UnauthorizedException("UNAUTHORIZED");
        }

        accessTokenRepository.deleteByToken(oldAccessToken);

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("deleted", true);

        return ResponseEntity.ok(new SuccessResponse(HttpStatus.OK.toString(), responseData));
    }

    /**
     * @param email email
     * @param password password
     * @return user
     * @throws ResourceNotFoundException The resource not found
     * @throws ValidationException       Validation error
     */
    private User authenticate(String email, String password) throws ResourceNotFoundException, ValidationException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new ResourceNotFoundException("USER_NOT_FOUND");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new ValidationException("INVALID_CREDENTIALS");
        }

        return user;
    }
}