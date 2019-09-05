package com.stransact.ssoexample;

import com.stransact.ssoexample.exceptions.ValidationException;
import com.stransact.ssoexample.models.*;
import com.stransact.ssoexample.repository.*;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.transaction.Transactional;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * The type Initial data loader
 *
 * @author moore.dagogohart
 */
@Component
public class InitialDataLoader implements ApplicationListener<ApplicationReadyEvent> {
    public InitialDataLoader(UserRepository userRepository, RoleRepository roleRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private boolean alreadySetup = false;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * @param event event
     */
    @Override
    @ExceptionHandler(ValidationException.class)
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (alreadySetup)
            return;

        Role employeeRole = createRoleIfNotFound("ROLE_EMPLOYEE");
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN");

        createUserIfNotFound(new HashSet<>(Arrays.asList(adminRole, employeeRole)), "moore@test.com");
        createUserIfNotFound(new HashSet<>(Arrays.asList(adminRole, employeeRole)), "temi@test.com");
        createUserIfNotFound(new HashSet<>(Arrays.asList(adminRole, employeeRole)), "tunde@test.com");
        createUserIfNotFound(new HashSet<>(Arrays.asList(adminRole, employeeRole)), "chieto@test.com");
        createUserIfNotFound(new HashSet<>(Arrays.asList(adminRole, employeeRole)), "festus@test.com");
        alreadySetup = true;
    }

    /**
     *
     * @param roles set of Roles
     * @param dept department
     * @return user
     */
    @Transactional
    protected User createUserIfNotFound(Set<Role> roles, String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            user = new User();
            user.setPassword(passwordEncoder.encode("testpassword"));
            user.setEmail(email);
            user.setRoles(roles);
            user = userRepository.save(user);
        }

        return user;
    }

    /**
     *
     * @param name string
     * @return role
     */
    @Transactional
    protected Role createRoleIfNotFound(String name) {

        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role();
            role.setName(name);
            role = roleRepository.save(role);
        }
        return role;
    }
}
